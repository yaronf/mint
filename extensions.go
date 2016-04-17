package mint

import (
	"bytes"
	"fmt"
	"encoding/binary"
)

type extensionBody interface {
	Type() helloExtensionType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ExtensionType extension_type;
//     opaque extension_data<0..2^16-1>;
// } Extension;
type extension struct {
	extensionType helloExtensionType
	extensionData []byte
}

func (ext extension) Marshal() ([]byte, error) {
	if len(ext.extensionData) > maxExtensionDataLen {
		return nil, fmt.Errorf("tls.extension: Extension data too long")
	}

	extLen := len(ext.extensionData)
	base := []byte{byte(ext.extensionType >> 8), byte(ext.extensionType),
		byte(extLen >> 8), byte(extLen)}
	return append(base, ext.extensionData...), nil
}

func (ext *extension) Unmarshal(data []byte) (int, error) {
	if len(data) < extensionHeaderLen {
		return 0, fmt.Errorf("tls.extension: Malformed extension; too short")
	}

	extDataLen := (int(data[2]) << 8) + int(data[3])
	if len(data) < extensionHeaderLen+extDataLen {
		return 0, fmt.Errorf("tls.extension: Malformed extension; incorrect length")
	}

	ext.extensionType = (helloExtensionType(data[0]) << 8) + helloExtensionType(data[1])
	ext.extensionData = data[extensionHeaderLen : extDataLen+extensionHeaderLen]
	return extensionHeaderLen + extDataLen, nil
}

type extensionList []extension

func (el extensionList) Marshal() ([]byte, error) {
	data := []byte{0x00, 0x00}

	for _, ext := range el {
		extBytes, err := ext.Marshal()
		if err != nil {
			return nil, err
		}

		data = append(data, extBytes...)
	}

	extensionsLen := len(data) - 2
	if extensionsLen > maxExtensionsLen {
		return nil, fmt.Errorf("tls.extensionlist: Extensions too long")
	}
	data[0] = byte(extensionsLen >> 8)
	data[1] = byte(extensionsLen)

	return data, nil
}

func (el *extensionList) Unmarshal(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("tls.extensionlist: Malformed extension list; too short")
	}
	extLen := (int(data[0]) << 8) + int(data[1])

	if len(data) < 2+extLen {
		return 0, fmt.Errorf("tls.extensionlist: Malformed extension list; incorrect extensions length")
	}
	extData := data[2 : extLen+2]

	var ext extension
	*el = []extension{}
	read := 0
	for read < extLen {
		n, err := ext.Unmarshal(extData[read:])
		if err != nil {
			return 0, err
		}

		*el = append(*el, ext)
		read += n
	}

	return 2 + extLen, nil
}

func (el *extensionList) Add(src extensionBody) error {
	data, err := src.Marshal()
	if err != nil {
		return err
	}

	*el = append(*el, extension{
		extensionType: src.Type(),
		extensionData: data,
	})
	return nil
}

func (el extensionList) Find(dst extensionBody) bool {
	for _, ext := range el {
		if ext.extensionType == dst.Type() {
			_, err := dst.Unmarshal(ext.extensionData)
			return err == nil
		}
	}
	return false
}

const (
	fixedKeyShareLen   = 4
	fixedServerNameLen = 5
)

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
//
// enum {
//     host_name(0), (255)
// } NameType;
//
// opaque HostName<1..2^16-1>;
//
// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
//
// But we only care about the case where there's a single DNS hostname.  We
// will never create anything else, and throw if we receive something else
//
//      2         1          2
// | listLen | NameType | nameLen | name |
type serverNameExtension string

func (sni serverNameExtension) Type() helloExtensionType {
	return extensionTypeServerName
}

func (sni serverNameExtension) Marshal() ([]byte, error) {
	nameLen := len(sni)
	listLen := 3 + nameLen
	data := make([]byte, 2+1+2+nameLen)

	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	data[2] = 0x00 // host_name
	data[3] = byte(nameLen >> 8)
	data[4] = byte(nameLen)
	copy(data[5:], []byte(sni))

	return data, nil
}

func (sni *serverNameExtension) Unmarshal(data []byte) (int, error) {
	if len(data) < fixedServerNameLen {
		return 0, fmt.Errorf("tls.servername: Too short for header")
	}

	listLen := (int(data[0]) << 8) + int(data[1])
	nameLen := (int(data[3]) << 8) + int(data[4])
	nameType := data[2]

	if listLen != nameLen+3 {
		return 0, fmt.Errorf("tls.servername: Length mismatch")
	}

	if nameType != 0x00 {
		return 0, fmt.Errorf("tls.servername: Unsupported name type")
	}

	if len(data) < fixedServerNameLen+nameLen {
		return 0, fmt.Errorf("tls.servername: Too short for name")
	}

	*sni = serverNameExtension(data[5 : 5+nameLen])
	return 5 + nameLen, nil
}

// struct {
//     NamedGroup group;
//     opaque key_exchange<1..2^16-1>;
// } KeyShareEntry;
type keyShare struct {
	group       namedGroup
	keyExchange []byte
}

// struct {
//     select (role) {
//         case client:
//             KeyShareEntry client_shares<4..2^16-1>;
//
//         case server:
//             KeyShareEntry server_share;
//     }
// } KeyShare;
type keyShareExtension struct {
	roleIsServer bool
	shares       []keyShare
}

func (ks keyShareExtension) Type() helloExtensionType {
	return extensionTypeKeyShare
}

func (ks keyShareExtension) Marshal() ([]byte, error) {
	if ks.roleIsServer && len(ks.shares) > 1 {
		return nil, fmt.Errorf("tls.keyshare: Server can only send one key share")
	}

	shares := []byte{}
	for _, share := range ks.shares {
		keyLen := len(share.keyExchange)
		keyLenForGroup := keyExchangeSizeFromNamedGroup(share.group)
		if keyLenForGroup > 0 && keyLen != keyLenForGroup {
			return nil, fmt.Errorf("tls.keyshare: Key exchange value has the wrong size")
		}

		header := []byte{byte(share.group >> 8), byte(share.group), byte(keyLen >> 8), byte(keyLen)}
		shares = append(shares, header...)
		shares = append(shares, share.keyExchange...)
	}

	if !ks.roleIsServer {
		dataLen := len(shares)
		header := []byte{byte(dataLen >> 8), byte(dataLen)}
		shares = append(header, shares...)
	}

	return shares, nil
}

func (ks *keyShareExtension) Unmarshal(data []byte) (int, error) {
	read := 0
	totalLen := len(data)
	if !ks.roleIsServer {
		if len(data) < 2 {
			return 0, fmt.Errorf("tls.keyshare: Client key share extension too short")
		}
		read = 2
		totalLen = (int(data[0]) << 8) + int(data[1])
	}

	for read < totalLen {
		if len(data[read:]) < fixedKeyShareLen {
			return 0, fmt.Errorf("tls.keyshare: Key share extension too short")
		}

		share := keyShare{}
		share.group = (namedGroup(data[read]) << 8) + namedGroup(data[read+1])
		keyLen := (int(data[read+2]) << 8) + int(data[read+3])
		if len(data[read+4:]) < keyLen {
			return 0, fmt.Errorf("tls.keyshare: Key share extension too short for key")
		}

		keyLenForGroup := keyExchangeSizeFromNamedGroup(share.group)
		if keyLenForGroup > 0 && keyLen != keyLenForGroup {
			return 0, fmt.Errorf("tls.keyshare: Key exchange value has the wrong size")
		}

		share.keyExchange = make([]byte, keyLen)
		copy(share.keyExchange, data[read+4:read+4+keyLen])
		ks.shares = append(ks.shares, share)

		read += 4 + keyLen

		if ks.roleIsServer {
			break
		}
	}

	return read, nil
}

// struct {
//     NamedGroup named_group_list<1..2^16-1>;
// } NamedGroupList;
type supportedGroupsExtension struct {
	groups []namedGroup
}

func (sg supportedGroupsExtension) Type() helloExtensionType {
	return extensionTypeSupportedGroups
}

func (sg supportedGroupsExtension) Marshal() ([]byte, error) {
	listLen := 2 * len(sg.groups)

	data := make([]byte, 2+listLen)
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	for i, group := range sg.groups {
		data[2*i+2] = byte(group >> 8)
		data[2*i+3] = byte(group)
	}

	return data, nil
}

func (sg *supportedGroupsExtension) Unmarshal(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("tls.supportedgroups: Too short for length")
	}

	listLen := (int(data[0]) << 8) + int(data[1])
	if len(data) < 2+listLen {
		return 0, fmt.Errorf("tls.supportedgroups: Too short for list")
	}
	if listLen%2 == 1 {
		return 0, fmt.Errorf("tls.supportedgroups: Odd list length")
	}
	sg.groups = make([]namedGroup, listLen/2)
	for i := range sg.groups {
		sg.groups[i] = (namedGroup(data[2*i+2]) << 8) + namedGroup(data[2*i+3])
	}

	return 2 + listLen, nil
}

// SignatureAndHashAlgorithm
//   supported_signature_algorithms<2..2^16-2>;
type signatureAlgorithmsExtension struct {
	algorithms []signatureAndHashAlgorithm
}

func (sa signatureAlgorithmsExtension) Type() helloExtensionType {
	return extensionTypeSignatureAlgorithms
}

func (sa signatureAlgorithmsExtension) Marshal() ([]byte, error) {
	listLen := 2 * len(sa.algorithms)

	data := make([]byte, 2+listLen)
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	for i, alg := range sa.algorithms {
		data[2*i+2] = byte(alg.hash)
		data[2*i+3] = byte(alg.signature)
	}

	return data, nil
}

func (sa *signatureAlgorithmsExtension) Unmarshal(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("tls.supportedgroups: Too short for length")
	}

	listLen := (int(data[0]) << 8) + int(data[1])
	if len(data) < 2+listLen {
		return 0, fmt.Errorf("tls.supportedgroups: Too short for list")
	}
	if listLen%2 == 1 {
		return 0, fmt.Errorf("tls.supportedgroups: Odd list length")
	}
	sa.algorithms = make([]signatureAndHashAlgorithm, listLen/2)
	for i := range sa.algorithms {
		sa.algorithms[i].hash = hashAlgorithm(data[2*i+2])
		sa.algorithms[i].signature = signatureAlgorithm(data[2*i+3])
	}

	return 2 + listLen, nil
}

// opaque psk_identity<0..2^16-1>;
//
// struct {
//     select (Role) {
//         case client:
//             psk_identity identities<2..2^16-1>;
//
//         case server:
//             psk_identity identity;
//     }
// } PreSharedKeyExtension;

type preSharedKeyExtension struct {
	roleIsServer bool
	identities   [][]byte
}

func (psk preSharedKeyExtension) Type() helloExtensionType {
	return extensionTypePreSharedKey
}

func (psk preSharedKeyExtension) Marshal() ([]byte, error) {
	if psk.roleIsServer && len(psk.identities) > 1 {
		return nil, fmt.Errorf("tls.presharedkey: Server can only send one identity")
	}

	identities := []byte{}
	for _, id := range psk.identities {
		idLen := len(id)
		header := []byte{byte(idLen >> 8), byte(idLen)}
		identities = append(identities, header...)
		identities = append(identities, id...)
	}

	if !psk.roleIsServer {
		dataLen := len(identities)
		header := []byte{byte(dataLen >> 8), byte(dataLen)}
		identities = append(header, identities...)
	}

	return identities, nil
}

func (psk *preSharedKeyExtension) Unmarshal(data []byte) (int, error) {
	read := 0
	totalLen := len(data)
	if !psk.roleIsServer {
		if len(data) < 2 {
			return 0, fmt.Errorf("tls.presharedkey: Client PSK extension too short")
		}
		read = 2
		totalLen = (int(data[0]) << 8) + int(data[1])
	}

	for read < 2+totalLen {
		if len(data[read:]) < 2 {
			return 0, fmt.Errorf("tls.presharedkey: PSK extension too short for identity header")
		}

		idLen := (int(data[read]) << 8) + int(data[read+1])
		if len(data[read+2:]) < idLen {
			return 0, fmt.Errorf("tls.presharedkey: PSK extension too short for identity")
		}

		id := make([]byte, idLen)
		copy(id, data[read+2:read+2+idLen])
		psk.identities = append(psk.identities, id)

		read += 2 + idLen

		if psk.roleIsServer {
			break
		}
	}

	return read, nil
}

func (psk preSharedKeyExtension) HasIdentity(id []byte) bool {
	for _, localID := range psk.identities {
		if bytes.Equal(localID, id) {
			return true
		}
	}
	return false
}

//   struct {
//       select (Role) {
//           case client:
//               opaque configuration_id<1..2^16-1>;
//               CipherSuite cipher_suite;
//               Extension extensions<0..2^16-1>;
//               opaque context<0..255>;
//
//           case server:
//              struct {};
//       }
//   } EarlyDataIndication;
//
//   | 2 | opaque | 2 | 2 | extList | 1 | opaque |

type earlyDataExtension struct {
	roleIsServer    bool
	configurationID []byte
	cipherSuite     cipherSuite
	extensions      extensionList
	context         []byte
	version         int
}

func (ed earlyDataExtension) Type() helloExtensionType {
	return extensionTypeEarlyData
}

func (ed earlyDataExtension) Marshal() ([]byte, error) {
	if ed.roleIsServer {
		return []byte{}, nil
	}

	extData, err := ed.extensions.Marshal()
	if err != nil {
		return nil, err
	}

	configLen := len(ed.configurationID)
	extLen := len(extData)
	contextLen := len(ed.context)

	if configLen > 0xFFFF {
		return nil, fmt.Errorf("tls.earlydata: ConfigurationID too large to marshal")
	}

	if contextLen > 0xFF {
		return nil, fmt.Errorf("tls.earlydata: Context too large to marshal")
	}

	data := make([]byte, 2+configLen+2+extLen+1+contextLen)
	data[0] = byte(configLen >> 8)
	data[1] = byte(configLen)
	copy(data[2:], ed.configurationID)
	data[2+configLen] = byte(ed.cipherSuite >> 8)
	data[2+configLen+1] = byte(ed.cipherSuite)
	copy(data[2+configLen+2:], extData)
	data[2+configLen+2+extLen] = byte(contextLen)
	copy(data[2+configLen+2+extLen+1:], ed.context)

	return data, nil
}

func (ed *earlyDataExtension) Unmarshal(data []byte) (int, error) {
	if ed.roleIsServer {
		return 0, nil
	}

	if len(data) < 2 {
		return 0, fmt.Errorf("tls.earlydata: Too short for config header")
	}

	configLen := (int(data[0]) << 8) + int(data[1])
	if len(data) < 2+configLen+2 {
		return 0, fmt.Errorf("tls.earlydata: Too short for config")
	}

	ed.configurationID = make([]byte, configLen)
	copy(ed.configurationID, data[2:])

	ed.cipherSuite = (cipherSuite(data[2+configLen]) << 8) + cipherSuite(data[2+configLen+1])

	extLen, err := ed.extensions.Unmarshal(data[2+configLen+2:])
	if err != nil {
		return 0, fmt.Errorf("tls.earlydata: Error unmarshaling extensions")
	}
	if len(data) < 2+configLen+2+extLen+1 {
		return 0, fmt.Errorf("tls.earlydata: Too short for context header")
	}

	contextLen := int(data[2+configLen+2+extLen])
	if len(data) < 2+configLen+2+extLen+1+contextLen {
		return 0, fmt.Errorf("tls.earlydata: Too short for context")
	}

	ed.context = make([]byte, contextLen)
	copy(ed.context, data[2+configLen+2+extLen+1:])

	return 2 + configLen + 2 + extLen + 1 + contextLen, nil
}

// This is required for NSS
type draftVersionExtension struct {
	version int
}

func (dv draftVersionExtension) Type() helloExtensionType {
	return extensionTypeDraftVersion
}

func (dv draftVersionExtension) Marshal() ([]byte, error) {
	return []byte{byte(dv.version >> 8), byte(dv.version)}, nil
}

func (dv *draftVersionExtension) Unmarshal(data []byte) (int, error) {
	if len(data) != 2 {
		return 0, fmt.Errorf("tls.draftVersion: Wrong length")
	}

	dv.version = (int(data[0]) << 8) + int(data[1])
	return 2, nil
}

type pinningTicketExtension struct {
	roleIsServer bool
	pinningTicket []byte
	pinningProof []byte
	lifetime uint32
}

func (pt pinningTicketExtension) Type() helloExtensionType {
	return extensionTypePinningTicket
}

// TODO: add proof-length to draft (1 byte)
func (pt pinningTicketExtension) Marshal() ([]byte, error) {
	if pt.roleIsServer {
		pte := []byte{}
		proofLen := len(pt.pinningProof)
		proofLenHeader := []byte{byte(proofLen)}
		lifetimeBytes := []byte{}
		binary.BigEndian.PutUint32(lifetimeBytes, pt.lifetime)
		pte = append(pte, proofLenHeader...)
		pte = append(pte, pt.pinningProof...)
		pte = append(pte, pt.pinningTicket...)
		pte = append(pte, lifetimeBytes...)
		return pte, nil
	} else { // client
		if pt.pinningTicket == nil || len(pt.pinningTicket) == 0 {
			return []byte{}, nil
		}
		return pt.pinningTicket, nil
	}
}

func (pt pinningTicketExtension) Unmarshal(data []byte) (int, error) {
	if pt.roleIsServer {
		proofLen := (int(data[0]) << 8) + int(data[1]) // may be 0
		pt.pinningProof = data[2:proofLen]
		pt.pinningTicket = data[2 + proofLen: len(data) - 4] // may be empty
		pt.lifetime = binary.BigEndian.Uint32(data[len(data) - 4:])
	} else {
		pt.pinningTicket = data // may be empty
	}
	return len(data), nil
}
