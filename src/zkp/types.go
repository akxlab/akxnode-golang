package zkp

import (
	"crypto/rand"
	"github.com/cloudflare/circl/oprf"
)

type Server struct {
	server oprf.Server
	vs     oprf.VerifiableServer
}

type Client struct {
	client oprf.Client
	v      oprf.VerifiableClient
}

type ZKP struct {
	c *Client
	s *Server
}

var suite oprf.Suite

func init() {
	suite, _ = oprf.GetSuite(3)
}

func (zkp *ZKP) Setup() {
	zkp.c = &Client{}
	zkp.c.client = oprf.NewClient(suite)
	sk, _ := oprf.GenerateKey(suite, rand.Reader)
	zkp.s = &Server{}
	zkp.s.server = oprf.NewServer(suite, sk)

	zkp.c.v = oprf.NewVerifiableClient(suite, sk.Public())
	zkp.s.vs = oprf.NewVerifiableServer(suite, sk)

}

func (zkp *ZKP) ZkpIT(inputs [][]byte) (bool, [][]byte) {
	inData, evalReq, _ := zkp.c.client.Blind(inputs)
	evaluation, _ := zkp.s.server.Evaluate(evalReq)
	outputs, err := zkp.c.client.Finalize(inData, evaluation)
	if err != nil {
		return false, nil
	}
	return true, outputs

}
