# TLS Controller Architecture Implementation Plan

## Overview
Refactor TLS connection handling to separate application layer from TLS Controller goroutine. The Controller manages all TLS state, encryption/decryption, and socket I/O after handshake completion.

**Key Constraint**: The application API is fully synchronous - only one operation (Read, Write, or KeyUpdate) can be in progress at a time. This simplifies the implementation significantly.

## KeyUpdate and key state

Per RFC 8446bis Section 4.6.3:

**Key Update Timing:**
- **Sender**: After sending a KeyUpdate message, the sender SHALL send all subsequent traffic (including application data) using the next generation of keys. The KeyUpdate message itself is encrypted with the old keys.
- **Receiver**: Upon receiving a KeyUpdate, the receiver MUST update its receiving keys. The receiver MUST enforce that a KeyUpdate with the old key is received before accepting any messages encrypted with the new key (to prevent message truncation attacks).

**Implementation Details:**
- When application data arrives encrypted with new keys before the KeyUpdate handshake is processed, decryption fails
- The record layer caches the failed decrypt attempt and returns `AlertWouldBlock`
- After processing the KeyUpdate handshake (which triggers `RekeyIn`), the cached record is retried with new keys
- This ensures KeyUpdate handshake messages are always processed before accepting application data encrypted with new keys

## Architecture

### Components

1. **Application Layer** (existing `Conn` struct)
   - Synchronous API: `Read()`, `Write()`, `initiateKeyUpdate()`, `Close()`
   - Communicates with Controller via channels
   - Initial handshake runs synchronously in application goroutine

2. **TLS Controller** (new goroutine)
   - Manages TLS state machine
   - Handles encryption/decryption
   - Owns socket I/O
   - Processes post-handshake messages (KeyUpdate, closure)
   - Runs in separate goroutine, started after handshake completes
   - The Controller is single-threaded and has no shared memory with the app, so no locking is required. To clarify: it receives the TLS Config and the TLS state (secrets etc.) when it starts, but they are stable at that point and so there's no ongoing sharing.

### Communication Channels

1. **`dataToSend`** (`chan []byte`, unbuffered)
   - Application → Controller
   - Data from `Write()` to be encrypted and sent
   - Unbuffered: Write() blocks until controller reads, ensuring synchronous behavior

2. **`dataToReceive`** (`chan []byte`, buffered, size 65536 = 64KB)
   - Controller → Application
   - Decrypted data for `Read()` to return
   - Buffered to allow controller to queue multiple records

3. **`commands`** (`chan controllerCommand`, buffered, size 1)
   - Application → Controller
   - Commands: KeyUpdate, Close
   - Buffered size 1 allows non-blocking sends

4. **`errors`** (`chan error`, buffered, size 1)
   - Controller → Application
   - Errors from Controller (connection errors, protocol errors)
   - Buffered to prevent blocking if application isn't reading

5. **`socketRecords`** (`chan *TLSPlaintext`, unbuffered)
   - Socket reader → Controller
   - Records read from socket for processing

6. **`socketErrors`** (`chan error`, unbuffered)
   - Socket reader → Controller
   - Errors from socket reads

7. **`controllerDone`** (`chan struct{}`, unbuffered)
   - Controller → Application
   - Signals controller goroutine shutdown

8. **`closed`** (`chan struct{}`, unbuffered)
   - Application → Controller
   - Signals connection closure

9. **`pendingKeyUpdateResponse`** (`chan struct{}`, created on-demand)
   - Controller internal
   - Signals when KeyUpdate response is received (for `requestUpdate=true` case)

## Implementation Steps

### Phase 1: Channel Infrastructure

1. **Add channel fields to `Conn` struct**
   ```go
   type Conn struct {
       // ... existing fields ...
       
   // Controller channels
   dataToSend     chan []byte
   dataToReceive  chan []byte
   commands       chan controllerCommand
   errors         chan error
   socketRecords  chan *TLSPlaintext // Records read from socket
   socketErrors   chan error          // Errors from socket reads
   controllerDone chan struct{}       // Signals controller shutdown
   closed         chan struct{}       // Signals connection closure
       
       // Controller state
       controllerRunning bool
       
       // KeyUpdate waiting state
       pendingKeyUpdateResponse chan struct{} // Signals when KeyUpdate response is received
   }
   ```

2. **Define command types**
   ```go
   type controllerCommandType int
   const (
       cmdKeyUpdate controllerCommandType = iota
       cmdClose
   )
   
   type controllerCommand struct {
       cmdType controllerCommandType
       // For KeyUpdate:
       requestUpdate bool
       // Result channel (unbuffered, Controller sends result here)
       result chan commandResult
   }
   
   type commandResult struct {
       err error
   }
   ```

3. **Initialize channels in `NewConn()`**
   - Create all channels (including `socketRecords` and `socketErrors`)
   - Set `controllerRunning = false`

### Phase 2: Controller Goroutine

1. **Create `startController()` method**
   - Called after handshake completes
   - Starts controller goroutine
   - Sets `controllerRunning = true`
   - **Note**: No mutex needed - only called once from Handshake() in application goroutine

2. **Implement socket reader goroutine**
   ```go
   func (c *Conn) socketReaderLoop() {
       for {
           // Read record from socket (blocking)
           pt, err := c.in.ReadRecord()
           if err != nil {
               // AlertWouldBlock means no data available yet (non-blocking mode)
               if err == AlertWouldBlock {
                   // Wait briefly before retrying to avoid busy-looping
                   select {
                   case <-time.After(1 * time.Millisecond):
                   case <-c.closed:
                       return
                   }
                   continue
               }
               // DecryptError might be due to KeyUpdate - cache and retry after RekeyIn
               // (handled by record layer's pendingDecryptRecord mechanism)
               select {
               case c.socketErrors <- err:
               case <-c.closed:
                   return
               }
               return
           }
           
           // Send record to controller
           select {
           case c.socketRecords <- pt:
           case <-c.closed:
               return
           }
       }
   }
   ```
   
   **Note**: The record layer handles decryption failures by caching encrypted records and retrying after `RekeyIn` (when KeyUpdate is processed). This ensures KeyUpdate handshake messages are processed before accepting application data encrypted with new keys.

3. **Implement `controllerLoop()` goroutine**
   ```go
   func (c *Conn) controllerLoop() {
       defer close(c.controllerDone)
       
       // Start socket reader goroutine
       go c.socketReaderLoop()
       
       for {
           select {
           case data := <-c.dataToSend:
               // Encrypt and send data
               c.handleDataToSend(data)
               
           case pt := <-c.socketRecords:
               // Record received from socket
               c.handleSocketRecord(pt)
               
           case err := <-c.socketErrors:
               // Socket error
               select {
               case c.errors <- err:
               case <-c.closed:
               }
               return
               
           case cmd := <-c.commands:
               // Handle command
               c.handleCommand(cmd)
               
           case <-c.closed:
               // Application closed connection
               return
           }
       }
   }
   ```
   
   **Note**: The socket reader runs in its own goroutine, allowing the controller's `select` to wait on both socket records and channels simultaneously.

4. **Implement `handleSocketRecord()`**
   ```go
   func (c *Conn) handleSocketRecord(pt *TLSPlaintext) {
       switch pt.contentType {
       case RecordTypeHandshake:
           // Process handshake message (KeyUpdate, etc.)
           // Note: RecordLayer.ReadRecord() already decrypts, so pt.fragment is decrypted
           c.processHandshakeRecord(pt)
           
       case RecordTypeApplicationData:
           // Decrypt and send to application
           // Note: RecordLayer.ReadRecord() already decrypts, so pt.fragment is decrypted
           decrypted := c.decryptRecord(pt) // Just returns pt.fragment
           select {
           case c.dataToReceive <- decrypted:
               // Successfully queued for application
           case <-c.closed:
               // Connection closed, discard data
           default:
               // Channel is full - should not happen in normal operation with 64KB buffer
               // Send error to application
               select {
               case c.errors <- errors.New("dataToReceive channel full"):
               case <-c.closed:
               }
           }
           
       case RecordTypeAlert:
           // Handle alert
           c.handleAlert(pt)
       }
   }
   ```
   
   **Note**: The record layer handles decryption. If decryption fails (e.g., application data encrypted with new keys before KeyUpdate is processed), the record layer caches the encrypted record and returns `AlertWouldBlock`. After processing the KeyUpdate handshake (which triggers `RekeyIn`), the next `ReadRecord()` call retries decryption with new keys.

5. **Implement `handleDataToSend()`**
   - Encrypt data using current keys
   - Write to socket
   - Block until sent (socket write is blocking)

6. **Implement `handleCommand()`**
   - Process `cmdKeyUpdate`: send KeyUpdate handshake message, update keys
   - Process `cmdClose`: send close_notify, close socket, return
   - Send result to `cmd.result` channel

### Phase 3: Refactor Application API

1. **Refactor `Read()`**
   ```go
   func (c *Conn) Read(buffer []byte) (int, error) {
       // Check for buffered data from before controller started
       if len(c.readBuffer) > 0 {
           n := copy(buffer, c.readBuffer)
           c.readBuffer = c.readBuffer[n:]
           return n, nil
       }
       
       // Ensure controller is running
       if !c.controllerRunning {
           return 0, errors.New("read called before controller started")
       }
       
       if len(buffer) == 0 {
           return 0, nil
       }
       
       // Wait for data from controller (blocks until data available)
       // Since application is synchronous, only one Read() can be active at a time
       if c.config.NonBlocking {
           // Non-blocking mode: return immediately if no data available
           select {
           case data := <-c.dataToReceive:
               n := copy(buffer, data)
               // TODO: Handle remainder if data is larger than buffer
               return n, nil
           case err := <-c.errors:
               return 0, err
           case <-c.closed:
               return 0, io.EOF
           default:
               return 0, AlertWouldBlock
           }
       } else {
           // Blocking mode: wait for data
           select {
           case data := <-c.dataToReceive:
               n := copy(buffer, data)
               // TODO: Handle remainder if data is larger than buffer
               return n, nil
           case err := <-c.errors:
               return 0, err
           case <-c.closed:
               return 0, io.EOF
           }
       }
   }
   ```
   
   **Note**: Since application is synchronous, only one Read() can be active at a time. This simplifies buffer management - we don't need to handle concurrent reads.

2. **Refactor `Write()`**
   ```go
   func (c *Conn) Write(data []byte) (int, error) {
       // Handle early data writes (before controller starts)
       if c.isClient && c.out.Epoch() == EpochEarlyData {
           // Early data: write directly to record layer (not through controller)
           // ... fragment and send records ...
           return len(data), nil
       }
       
       // Ensure controller is running for post-handshake writes
       if !c.controllerRunning {
           return 0, errors.New("write called before controller started")
       }
       
       // Send data to controller (blocks until controller accepts)
       // Since application is synchronous, only one Write() can be active at a time
       // dataToSend is unbuffered, so this blocks until controller reads
       if c.config.NonBlocking {
           // Non-blocking mode: return immediately if channel is full
           select {
           case c.dataToSend <- data:
               return len(data), nil
           case err := <-c.errors:
               return 0, err
           case <-c.closed:
               return 0, io.EOF
           default:
               return 0, AlertWouldBlock
           }
       } else {
           // Blocking mode: wait until controller accepts data
           select {
           case c.dataToSend <- data:
               return len(data), nil
           case err := <-c.errors:
               return 0, err
           case <-c.closed:
               return 0, io.EOF
           }
       }
   }
   ```
   
   **Note**: Since application is synchronous, only one Write() can be active at a time. The write blocks until the controller accepts the data. `dataToSend` is unbuffered to ensure synchronous behavior.

3. **Implement `initiateKeyUpdate()`**
   ```go
   func (c *Conn) initiateKeyUpdate(requestUpdate bool) error {
       if !c.controllerRunning {
           return errors.New("KeyUpdate called before handshake completed")
       }
       
       // Create command
       resultChan := make(chan commandResult, 1)
       cmd := controllerCommand{
           cmdType: cmdKeyUpdate,
           requestUpdate: requestUpdate,
           result: resultChan,
       }
       
       // Send command (blocks until controller accepts)
       select {
       case c.commands <- cmd:
           // Wait for result (blocks until complete)
           result := <-resultChan
           return result.err
       case err := <-c.errors:
           return err
       case <-c.closed:
           return io.EOF
       }
   }
   ```

4. **Refactor `Close()`**
   ```go
   func (c *Conn) Close() error {
       if !c.controllerRunning {
           // Controller not running, just close the connection
           return c.conn.Close()
       }
       
       // Close the closed channel to signal shutdown
       select {
       case <-c.closed:
           // Already closed
       default:
           close(c.closed)
       }
       
       // Send close command
       resultChan := make(chan commandResult, 1)
       cmd := controllerCommand{
           cmdType: cmdClose,
           result:  resultChan,
       }
       
       select {
       case c.commands <- cmd:
           // Wait for controller to close
           <-resultChan
           <-c.controllerDone // Wait for goroutine to exit
           return nil
       case <-c.controllerDone:
           // Controller already closed
           return nil
       case <-c.closed:
           // Already closed
           return nil
       }
   }
   ```
   
   **Note**: No mutex needed for `controllerRunning` because the API is synchronous - only one operation (Read/Write/Close) can be active at a time from the application goroutine.

### Phase 4: Handshake Integration

1. **Modify `Handshake()`**
   - Keep existing synchronous handshake logic
   - After handshake completes successfully:
     - Call `startController()`
     - Set `controllerRunning = true`

2. **Ensure handshake state is accessible to Controller**
   - Controller needs access to:
     - Current cipher suite and keys
     - State machine state
     - Record layer for encryption/decryption

### Phase 5: State Machine Integration

1. **Controller processes post-handshake messages**
   - KeyUpdate: update keys, send response if requested
   - Close: handle close_notify, shutdown gracefully

2. **KeyUpdate handling in Controller**
   ```go
   func (c *Conn) handleKeyUpdateCommand(cmd controllerCommand) {
       // Convert requestUpdate bool to KeyUpdateRequest enum
       request := KeyUpdateNotRequested
       if cmd.requestUpdate {
           request = KeyUpdateRequested
       }
       
       // Generate KeyUpdate message and get actions (send KeyUpdate, RekeyOut)
       actions, alert := (&c.state).KeyUpdate(request)
       if alert != AlertNoAlert {
           c.sendAlert(alert)
           cmd.result <- commandResult{err: fmt.Errorf("alert while generating key update: %v", alert)}
           return
       }
       
       // Take actions (send KeyUpdate message, update sender keys via RekeyOut)
       for _, action := range actions {
           actionAlert := c.takeAction(action)
           if actionAlert != AlertNoAlert {
               c.sendAlert(actionAlert)
               cmd.result <- commandResult{err: fmt.Errorf("alert during key update actions: %v", actionAlert)}
               return
           }
       }
       
       // If requestUpdate=true, wait for peer's KeyUpdate response
       if cmd.requestUpdate {
           // Create channel to wait for peer's KeyUpdate response
           // Note: No mutex needed - controller is single-threaded and API is synchronous
           // Only one KeyUpdate can be in progress at a time
           if c.pendingKeyUpdateResponse != nil {
               // Already waiting for a KeyUpdate response - error
               cmd.result <- commandResult{err: errors.New("KeyUpdate already in progress")}
               return
           }
           c.pendingKeyUpdateResponse = make(chan struct{})
           
           // Wait for peer's KeyUpdate response
           // This will be signaled by processHandshakeRecord when it receives the KeyUpdate message
           select {
           case <-c.pendingKeyUpdateResponse:
               // Peer's KeyUpdate response received and processed (RekeyIn already done)
               c.pendingKeyUpdateResponse = nil
               cmd.result <- commandResult{err: nil}
           case err := <-c.errors:
               c.pendingKeyUpdateResponse = nil
               cmd.result <- commandResult{err: err}
           case <-c.closed:
               c.pendingKeyUpdateResponse = nil
               cmd.result <- commandResult{err: io.EOF}
           }
           return
       }
       
       cmd.result <- commandResult{err: nil}
   }
   ```
   
   **Key Update Flow:**
   - **Sending KeyUpdate**: Generate message → Send with old keys → RekeyOut (update sender keys) → All subsequent traffic uses new keys
   - **Receiving KeyUpdate**: Receive message encrypted with old keys → Process via state machine → RekeyIn (update receiver keys) → Signal completion if waiting for response

3. **State transitions**
   - Controller maintains `stateConnected` state
   - Updates keys in place
   - No state transitions for KeyUpdate (stays in connected state)

### Phase 6: Error Handling

1. **Controller error propagation**
   - Socket errors → send to `errors` channel
   - Protocol errors → send to `errors` channel
   - Decryption errors → handled by record layer:
     - If decryption fails, record layer caches encrypted record and returns `AlertWouldBlock`
     - After KeyUpdate is processed (RekeyIn), cached record is retried with new keys
     - Only fatal decryption errors (after retry) are sent to `errors` channel

2. **Application error handling**
   - `Read()`/`Write()` check `errors` channel
   - Return errors to caller
   - Close connection on fatal errors

### Phase 7: Non-Blocking Mode

1. **Handle `NonBlocking` config**
   - `Read()`: if `dataToReceive` empty, return `AlertWouldBlock`
   - `Write()`: if `dataToSend` full, return `AlertWouldBlock`
   - Controller: use non-blocking socket operations

### Phase 8: Testing

1. **Update existing tests**
   - Tests should work with new architecture
   - May need to adjust timing expectations

2. **Add new tests**
   - Test controller goroutine lifecycle
   - Test channel communication
   - Test Read/Write operations (synchronous, one at a time)
   - Test KeyUpdate via controller
   - Test error propagation
   - Test backpressure (full buffers)

## Migration Strategy

1. **Keep existing code working**
   - Implement Controller alongside existing code
   - Switch to Controller after handshake completes
   - Remove old code paths after Controller is stable

2. **Gradual migration**
   - Phase 1-2: Add Controller infrastructure, don't use it yet
   - Phase 3-4: Switch Read/Write to use Controller
   - Phase 5-6: Add KeyUpdate and error handling
   - Phase 7-8: Add non-blocking support and tests

## Design Decisions

1. **Socket ownership**
   - Application goroutine owns socket during handshake
   - Controller owns socket after handshake completes
   - If socket error occurs during handshake: connection setup fails, handshake returns error

2. **Buffer management**
   - `dataToReceive` buffers complete decrypted application data records (64KB buffer)
   - `Read()` handles partial reads by copying available data to user buffer
   - Controller sends full decrypted records to `dataToReceive`
   - **Note**: Current implementation assumes each record is fully consumed by Read(). Partial record handling (storing remainder) may need refinement.
   - `readBuffer` stores data read before controller started (e.g., early data, buffered records)

3. **Backpressure handling**
   - `dataToSend` is unbuffered: `Write()` blocks until controller reads (synchronous behavior)
   - If `dataToReceive` is full: Controller sends error to `errors` channel, connection may need to be closed
   - **Implementation**: Controller checks channel capacity before sending, sends error if full
   - In non-blocking mode: `Write()` returns `AlertWouldBlock` if controller isn't ready, `Read()` returns `AlertWouldBlock` if no data available

4. **Synchronous application API**
   - **Critical**: Application operations are fully synchronous
   - Only one operation at a time: Read OR Write OR KeyUpdate
   - No concurrent Read/Write operations
   - No multiple Write() calls in flight
   - This simplifies implementation - no need for complex synchronization
   - **No mutexes needed**: Since the API is synchronous and the controller is single-threaded:
     - `controllerRunning` flag is only accessed from application goroutine (synchronous API)
     - `pendingKeyUpdateResponse` is only accessed from controller goroutine (single-threaded)
     - No concurrent access = no race conditions = no mutexes needed

5. **KeyUpdate timing and key update order**
   - **Sending KeyUpdate**: 
     - Generate and send KeyUpdate message (encrypted with old keys)
     - Execute RekeyOut action (update sender keys)
     - All subsequent application data uses new keys
   - **Receiving KeyUpdate**:
     - Receive KeyUpdate message (encrypted with old keys)
     - Process via state machine
     - Execute RekeyIn action (update receiver keys)
     - If this is a response to our requestUpdate=true, signal completion
   - **KeyUpdate blocks until complete**
     - If `requestUpdate=true`, waits for peer's KeyUpdate response before returning
     - Uses `pendingKeyUpdateResponse` channel to wait for response
   - **Controller processes incoming KeyUpdate messages asynchronously**
     - Incoming KeyUpdate messages are processed in `processHandshakeRecord()`
     - If we're waiting for a response, `processHandshakeRecord()` signals completion
   - **Decryption retry mechanism**:
     - If application data arrives encrypted with new keys before KeyUpdate is processed, decryption fails
     - Record layer caches the encrypted record and returns `AlertWouldBlock`
     - After processing KeyUpdate (RekeyIn), cached record is retried with new keys
     - This ensures KeyUpdate handshake is always processed before accepting new-key-encrypted data

## Implementation Status

### Completed ✅

1. ✅ Channel infrastructure (Phase 1)
   - All channels defined and initialized in `NewConn()`
   - Command types defined (`controllerCommand`, `commandResult`)
   - KeyUpdate waiting state (`pendingKeyUpdateResponse`)
   - **Note**: No mutexes needed - controller is single-threaded and API is synchronous

2. ✅ Controller goroutine skeleton (Phase 2)
   - `startController()` method implemented
   - `controllerLoop()` main loop implemented
   - `socketReaderLoop()` implemented with AlertWouldBlock handling

3. ✅ Socket reading logic (Phase 2)
   - Socket reader goroutine reads records and sends to controller
   - Handles AlertWouldBlock for non-blocking mode
   - Record layer implements decryption retry mechanism for KeyUpdate

4. ✅ Refactor Read/Write (Phase 3)
   - `Read()` refactored to use `dataToReceive` channel
   - `Write()` refactored to use `dataToSend` channel
   - Early data handling (writes directly to record layer before controller starts)
   - Non-blocking mode support implemented

5. ✅ Handshake integration (Phase 4)
   - `Handshake()` calls `startController()` after completion
   - Controller has access to state machine and record layers

6. ✅ KeyUpdate handling (Phase 5)
   - `handleKeyUpdateCommand()` implemented
   - KeyUpdate message generation and sending
   - RekeyOut/RekeyIn actions executed
   - Waiting for peer response when `requestUpdate=true`
   - `processHandshakeRecord()` processes incoming KeyUpdate messages

7. ✅ Error handling (Phase 6)
   - Socket errors propagated via `errors` channel
   - Protocol errors sent to `errors` channel
   - Decryption errors handled by record layer retry mechanism
   - Alert handling implemented

8. ✅ Non-blocking mode (Phase 7)
   - `Read()` returns `AlertWouldBlock` if no data available
   - `Write()` returns `AlertWouldBlock` if channel not ready
   - Socket reader handles AlertWouldBlock with retry delay

### Remaining Work

9. ⏳ Testing (Phase 8)
   - Update existing tests for new architecture
   - Add tests for controller goroutine lifecycle
   - Add tests for KeyUpdate with requestUpdate=true
   - Add tests for decryption retry mechanism
   - Add tests for error propagation
   - Add tests for backpressure scenarios

### Implementation Notes

- **Record Layer Decryption Retry**: The record layer (`record-layer.go`) implements a sophisticated mechanism to handle the case where application data arrives encrypted with new keys before the KeyUpdate handshake is processed. It caches the encrypted record and retries after `RekeyIn`.
- **Channel Configuration**: `dataToSend` is unbuffered to ensure synchronous behavior (Write() blocks until controller processes). `dataToReceive` is buffered (64KB) to allow queuing multiple records.
- **Early Data**: Client early data writes bypass the controller and write directly to the record layer, as the controller only starts after handshake completion.

