package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"net"

	"akxsystem/src/config"
)

var pks []kyber.Point

type Network struct {
	SelfNode        *AKXNode
	Nodes           map[string]*AKXNode
	ns              []*AKXNode
	BlackList       map[string]bool
	suite           *edwards25519.SuiteEd25519
	proofs          []*dkg.Justification
	ID              []byte
	qualifiedPubKey kyber.Point
}

type AKXNode struct {
	ID        ID
	cfg       *config.P2PConfig
	events    interface{}
	quit      chan bool
	router    interface{}
	pool      interface{}
	isEvm     bool
	layerType uint // 1-2-3
	dkm       *DistributedKeyManager
	netID     []byte
}

type Server struct {
	tcp *net.TCPConn
}

type DistributedKeyManager struct {
	dkg         *dkg.DistKeyGenerator
	pubKey      kyber.Point
	privKey     kyber.Scalar
	deals       []*dkg.Deal
	responses   []*dkg.Response
	secretShare *share.PriShare
}

func NewNode(cfg *config.P2PConfig) *AKXNode {

	id := GenerateNewID()
	anode := &AKXNode{}
	anode.ID = id

	anode.cfg = cfg
	dkm := &DistributedKeyManager{}
	dkm.deals = make([]*dkg.Deal, 0)
	dkm.responses = make([]*dkg.Response, 0)
	return anode
}

func NewNetwork() *Network {
	n := &Network{}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n.suite = suite
	n.Nodes = make(map[string]*AKXNode)
	n.BlackList = make(map[string]bool)
	n.ns = make([]*AKXNode, 100)

	return n
}

func (n *Network) InitNode() {
	cfg := &config.P2PConfig{}
	cfg.SetDefaults()
	node := NewNode(cfg)
	node.dkm.privKey = n.suite.Scalar().Pick(n.suite.RandomStream())
	node.dkm.pubKey = n.suite.Point().Mul(node.dkm.privKey, nil)
	n.AddSelf(node)
}

func (n *Network) AddSelf(node *AKXNode) {
	n.SelfNode = node
	n.Nodes[node.ID.String()] = node
}

func (n *Network) AddPeer(node *AKXNode) error {

	if n.isBlacklisted(node.ID.String()) {
		return errors.New("node id is blacklisted disconnecting")
	}
	if bytes.Equal(node.ID.Bytes(), n.SelfNode.ID.Bytes()) {
		return errors.New("cannot add self node")
	}
	if !bytes.Equal(n.ID, node.netID) {
		return errors.New("invalid network id")
	}

	if len(n.ns) == 99 {
		return errors.New("maximum nodes limit reached for network")
	}
	n.Nodes[node.ID.String()] = node
	n.ns[len(n.ns)] = node
	return nil
}

func (n *Network) pubKeys() []kyber.Point {

	for i, node := range n.ns {
		pks[i] = node.dkm.pubKey
	}
	return pks
}

func (n *Network) initDKGs() {
	for i, node := range n.ns {
		dkg1, err := dkg.NewDistKeyGenerator(n.suite, n.ns[i].dkm.privKey, n.pubKeys(), len(n.ns))
		if err != nil {
			panic(err)
		}
		node.dkm.dkg = dkg1
	}
}

func (n *Network) isBlacklisted(id string) bool {
	return n.BlackList[id] == true
}

/* NETWORK CONSENSUS POST-QUANTUM KYBER DKG */

func (n *Network) StartConsensus() {
	for i, node := range n.ns {
		deals, err := node.dkm.dkg.Deals()
		if err != nil {
			n.ejectInvalidNode(node, i, errors.New("invalid node"))
		}
		// each node sends its deals to other nodes
		for i, deal := range deals {
			n.ns[i].dkm.deals = append(n.ns[i].dkm.deals, deal)
		}

	}
}

func (n *Network) processResponses() {
	for i, node := range n.ns {
		for _, resp := range node.dkm.responses {

			proof, err := node.dkm.dkg.ProcessResponse(resp)
			if err != nil {
				n.ejectInvalidNode(node, i, errors.New("invalid response"))
			}
			n.proofs = append(n.proofs, proof)
		}
	}
}

func (n *Network) verifyProofs() {
	for _, proof := range n.proofs {
		for i, node := range n.ns {
			err := node.dkm.dkg.ProcessJustification(proof)
			if err != nil {
				n.ejectInvalidNode(node, i, errors.New("invalid proof"))
			}
		}
	}
}

func (n *Network) ejectInvalidNode(node *AKXNode, index int, err error) {
	nodeID := node.ID.String()
	if index < 0 || index >= len(n.ns) {
		fmt.Println("The given index is out of bounds.")
		panic(err)
	} else {
		newNode := append(n.ns[:index], n.ns[index+1:]...)
		n.ns = newNode
	}
	delete(n.Nodes, nodeID)
	fmt.Printf("ejected invalid node: %s reason: %v", nodeID, err)

}

var nonce int

type ConsensusInfo struct {
	round        int
	participants []string
	shares       map[string]dkg.DistKeyShare
	signatures   map[string][]byte
	numShares    int
}

func (n *Network) GetShares() map[string][]int {
	shares := make(map[string][]int)
	for _, node := range n.ns {
		if node.dkm.dkg.Certified() && node.dkm.dkg.ThresholdCertified() {
			shares[node.ID.String()] = node.dkm.dkg.QualifiedShares()
		}
	}
	nonce++
	return shares
}

func (n *Network) SetQualifiedPubKey(cInfo *ConsensusInfo) error {
	shares := make([]*share.PriShare, cInfo.numShares)
	var pub kyber.Point
	for i, node := range n.ns {
		dKey, err := node.dkm.dkg.DistKeyShare()
		if err != nil {
			return err
		}
		shares[i] = dKey.PriShare()
		pub = dKey.Public()
		node.dkm.secretShare = dKey.PriShare()

	}
	n.qualifiedPubKey = pub
	return nil
}

type EncryptedEnvelope struct {
	ps  []*share.PubShare
	C   kyber.Point
	p   kyber.Scalar
	cnt int
}

func (n *Network) Encryptor(nodeID string, message []byte, cInfo *ConsensusInfo) *EncryptedEnvelope {
	A := n.Nodes[nodeID].dkm.pubKey
	r := n.suite.Scalar().Pick(n.suite.RandomStream())
	M := n.suite.Point().Embed(message, n.suite.RandomStream())
	//_, C, _ := ElGamalEncrypt(n.suite, n.qualifiedPubKey, message)
	E := &EncryptedEnvelope{}

	E.C = n.suite.Point().Add( // rA + M
		n.suite.Point().Mul(r, A), // rA
		M,
	)
	U := n.suite.Point().Mul(r, nil)
	p := n.suite.Scalar().Pick(n.suite.RandomStream())
	Q := n.suite.Point().Mul(p, nil) // pG

	partials := make([]kyber.Point, cInfo.numShares)
	pubShares := make([]*share.PubShare, cInfo.numShares) // V1, V2, ...Vi
	for i, node := range n.ns {
		v := n.suite.Point().Add( // oU + oQ
			n.suite.Point().Mul(node.dkm.secretShare.V, U), // oU
			n.suite.Point().Mul(node.dkm.secretShare.V, Q), // oQ
		)
		partials[i] = v
		pubShares[i] = &share.PubShare{
			I: i, V: partials[i],
		}
	}
	E.cnt = cInfo.numShares
	E.ps = pubShares
	return E
}

func (n *Network) Decrypted(nodeID string, e *EncryptedEnvelope) []byte {
	R, err := share.RecoverCommit(n.suite, e.ps, e.cnt, e.cnt) // R = f(V1, V2, ...Vi)
	if err != nil {
		panic(err)
	}

	decryptedPoint := n.suite.Point().Sub( // C - (R - pA)
		e.C,
		n.suite.Point().Sub( // R - pA
			R,
			n.suite.Point().Mul(e.p, n.Nodes[nodeID].dkm.pubKey), // pA
		),
	)
	decryptedMessage, err := decryptedPoint.Data()
	if err != nil {
		panic(err)
	}
	return decryptedMessage
}
