package writebtcOld

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcrpcclient"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"time"
	"writebtc"
)

/**
	Btc provides access to the Bitcoin blockchain

	init()     starts everything up.
	shutdown() shuts it all down.
**/
type Btc struct {
	ID         int
	Client     *btcrpcclient.Client
	sourceAdrs []*btcutil.Address
	sources    []string
	srcIndex   int
	balance    int64
}

func (b *Btc) Shutdown() {
	// For this example gracefully shutdown the Client after 10 seconds.
	// Ordinarily when to shutdown the Client is highly application
	// specific.
	log.Println("Client shutdown in 2 seconds...")
	time.AfterFunc(time.Second*2, func() {
		log.Println("Going down...")
		b.Client.Shutdown()
	})
	defer log.Println("Shutdown done!")
	// Wait until the client either shuts down gracefully (or the user
	// terminates the process with Ctrl+C).
	b.Client.WaitForShutdown()
}

var counter int = 1

func (b *Btc) Init(sources []string ) (b2 *Btc, err error) {
	b.ID = counter
	counter++
	
	// Only override the handlers for notifications you care about.
	// Also note most of the handlers will only be called if you register
	// for notifications.  See the documentation of the btcrpcclient
	// NotificationHandlers type for more details about each handler.
	ntfnHandlers := btcrpcclient.NotificationHandlers{
		OnAccountBalance: func(account string, balance btcutil.Amount, confirmed bool) {
			go b.NewBalance(account, balance, confirmed)
		},

		OnBlockConnected: func(hash *btcwire.ShaHash, height int32) {
			go b.newBlock(hash, height)
		},
	}
	
	// Copy the sources
	b.SetSources(sources)

	// Connect to local btcwallet RPC server using websockets.
	certHomeDir := btcutil.AppDataDir("btcwallet", false)
	certs, err := ioutil.ReadFile(filepath.Join(certHomeDir, "rpc.cert"))
	if err != nil {
		log.Println(err)
		return
	}

	connCfg := &btcrpcclient.ConnConfig{
		Host:         "localhost:18332",
		Endpoint:     "ws",
		User:         "testuser",
		Pass:         "notarychain",
		Certificates: certs,
	}

	b.Client, err = btcrpcclient.New(connCfg, &ntfnHandlers)

	log.Println("in Init, Client: ", b.ID, b.Client)

	if err != nil || b.Client == nil {
		log.Println(err)
		if b.Client == nil {
			log.Println("client is nil")
		}
		return
	}

	b.srcIndex = 0

	for _, adr := range b.sources {

		cadr, err2 := btcutil.DecodeAddress(adr, writebtc.ActiveNet.Params)
		err = err2

		if err != nil {
			return
		}

		b.sourceAdrs = append(b.sourceAdrs, &cadr)

	}

	return
}
/**
 * Set the Bitcoin sources up for Btc.  It is these addresses that will
 * be used to record information into the blockchain.
 **/
func (b *Btc) SetSources(sources []string) {
   b.sources = make([]string, len(sources),len(sources)) 
   copy(b.sources, sources)
}

// Enodes up to 30 bytes into a 33 byte Bitcoin public key.
// Returns the public key.  The format is as follows:
// 1      byte   02  (per Bitcoin spec)
// 1      byte   len (Number of bytes encoded, between 1 and 63)
// len    bytes  encoded data
// 30-len bytes  random data
// fudge  byte   changed to put the value on the eliptical curve
//
func (*Btc) Encode(hash []byte) ([]byte, error) {
	length := len(hash)
	if length == 0 || length > 30 {
		return nil, errors.New("Encode can only handle 1 to 30 bytes")
	}
	var b []byte = make([]byte, 0, 33)
	b = append(b, byte(2), byte(length))

	b = append(b, hash...)

	if length < 30 {
		data := make([]byte, 30-length)
		b = append(b, data...)
	}

	b = append(b, byte(0))

	for i := 0; i < 256; i++ {
		b[len(b)-1] = byte(i)
		adr2 := hex.EncodeToString(b)
		_, e := btcutil.DecodeAddress(adr2, writebtc.ActiveNet.Params)
		if e == nil {
			return b, nil
		}
	}

	log.Print("Failure")
	return b, errors.New("Couldn't fix the address")
}

//
// Faithfully extracts upto 30 bytes encoded into the given bitcoin address
func (*Btc) Decode(addr []byte) []byte {
	length := int(addr[1])
	data := addr[2 : length+2]
	return data
}

// Compute the balance for the currentAddr, and the list of its unspent
// outputs
func (b *Btc) ComputeBalance(cAddr *btcutil.Address) (cAmount btcutil.Amount, cList []btcjson.TransactionInput, err error) {

	// Get the list of unspent transaction outputs (utxos) that the
	// connected wallet has at least one private key for.

	unspent, e := b.Client.ListUnspent()
	if e != nil {
		err = e
		return
	}

	// This is going to be our map of addresses to all unspent outputs
	var outputs = make(map[string][]btcjson.ListUnspentResult)

	for _, input := range unspent {
		l, n := outputs[input.Address] // Get the list of
		if !n {
			l = make([]btcjson.ListUnspentResult, 1)
			l[0] = input
			outputs[input.Address] = l
		} else {
			outputs[input.Address] = append(l, input)
		}
	}

	for index, unspentList := range outputs {
		if strings.EqualFold(index, (*cAddr).EncodeAddress()) {
			cAmount = btcutil.Amount(0)
			for i := range unspentList {
				cAmount += btcutil.Amount(unspentList[i].Amount * float64(100000000))
			}
			cList = make([]btcjson.TransactionInput, len(unspentList), len(unspentList))
			for i, u := range unspentList {
				v := new(btcjson.TransactionInput)
				v.Txid = u.TxId
				v.Vout = u.Vout
				cList[i] = *v
			}
		}
	}
	return
}

func (b *Btc) PrintBalance() {
	// Get the list of unspent transaction outputs (utxos) that the
	// connected wallet has at least one private key for.

	unspent, e := b.Client.ListUnspent()
	if e != nil {
		return
	}

	// This is going to be our map of addresses to all unspent outputs
	var outputs = make(map[string][]btcjson.ListUnspentResult)

	for _, input := range unspent {
		log.Println(input)
		l, n := outputs[input.Address] // Get the list of
		if !n {
			l = make([]btcjson.ListUnspentResult, 1)
			l[0] = input
			outputs[input.Address] = l
		} else {
			outputs[input.Address] = append(l, input)
		}
	}

	for index, unspentList := range outputs {
		// figure balance
		b := btcutil.Amount(0)
		for i := range unspentList {
			b = b + btcutil.Amount(unspentList[i].Amount*float64(100000000))
		}
		log.Print(index, " balance: ", b)
	}

}

func (b *Btc) NewBalance(account string, balance btcutil.Amount, confirmed bool) {
	sconf := "unconfirmed"
	if confirmed {
		sconf = "confirmed"
	}
	log.Printf("New %s balance for account %s: %v", sconf, account, balance)
}

/**
 * Record a hash into the Bitcoin Block Chain Multisig
**/
func (b *Btc) RecordHash(hash []byte) (txhash *btcwire.ShaHash, err error) {

	txhash = nil

	if len(hash) != 32 {
		err = fmt.Errorf("len(hash) = %d \n Note that hash[] must be 32 bytes in length", len(hash))
		return
	}

	b0, _ := b.Encode(hash[:16])
	adr0 := hex.EncodeToString(b0)
	b1, _ := b.Encode(hash[16:])
	adr1 := hex.EncodeToString(b1)

	address := make([]string, 2, 2)
	decodeAdr := make([]btcutil.Address, 2, 2)
	results := make([]*btcjson.ValidateAddressResult, 2, 2)

	address[0] = adr0 //external compressed public key
	address[1] = adr1 //external compressed public key

	for i := 0; i < len(address); i++ {

		decodeAdr[i], err = btcutil.DecodeAddress(address[i], writebtc.ActiveNet.Params)
		if err != nil {
			log.Print("Error decoding addr ", i, err)
			return
		}

		log.Println(b.Client)

		results[i], err = b.Client.ValidateAddress(decodeAdr[i])
		if err != nil {

			log.Print("Error validating addr ", i, err)
			return
		}

	}

	currentAddr := b.sourceAdrs[b.srcIndex]

	log.Print("source: ", b.sources[b.srcIndex], " index: ", b.srcIndex)

	b.srcIndex = (b.srcIndex + 1) % len(b.sourceAdrs)

	addressSlice := append(make([]btcutil.Address, 0, 3), *currentAddr, decodeAdr[0], decodeAdr[1])

	multiAddr, e := b.Client.AddMultisigAddress(1, addressSlice, "")

	if e != nil {
		log.Print("Reported Error: ", multiAddr, e)
		return
	}

	amount, unspent, err0 := b.ComputeBalance(currentAddr)
	if err0 != nil {
		log.Print("Error computing the balance")
		return
	}
	fee, err1 := btcutil.NewAmount(.0005)
	if err1 != nil {
		log.Print("Error create a new amount")
		return
	}
	change := amount - 5430 - fee
	send, err2 := btcutil.NewAmount(.00005430)
	if err2 != nil {
		log.Print("Error calculating change")
		return
	}

	log.Print("Amount at the address:  ", amount)
	log.Print("Change after the trans: ", change)
	log.Print("Amount to send:         ", send)
	log.Print("Send+Change+fee:        ", send+change+fee)
	log.Print("unspent: ", unspent)

	adrs := make(map[btcutil.Address]btcutil.Amount)
	adrs[multiAddr] = send
	// dest, _ := btcutil.DecodeAddress("mnyUYs1SJFQEKSLFZoGUsUTk8mZbbt37Ge", activeNet.Params);
	// adrs[dest] = send
	adrs[*currentAddr] = change
	rawTrans, err3 := b.Client.CreateRawTransaction(unspent, adrs)

	if err3 != nil {
		log.Print("raw trans create failed", err3)
		return
	}

	signedTrans, inputsSigned, err4 := b.Client.SignRawTransaction(rawTrans)

	if err4 != nil {
		log.Print("Failed to sign transaction ", err4)
		return
	}

	if !inputsSigned {
		log.Print("Inputs are not signed;  Is your wallet unlocked? ")
		return
	}

	txhash, err = b.Client.SendRawTransaction(signedTrans, false)

	if err != nil {
		log.Print("Transaction submission failed", err)
		return
	}

	return
}

/**
 * Record a hash into the Bitcoin Block Chain OP_RETURN
**/
func (b *Btc) RecordHashOR(hash []byte) (txhash *btcwire.ShaHash, err error) {

	txhash = nil

	if len(hash) != 32 {
		err = fmt.Errorf("len(hash) = %d \n Note that hash[] must be 32 bytes in length", len(hash))
		return
	}

	header := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	hash = append(header, hash...)

	var currentAddr *btcutil.Address
	var currentAddrTxt string
	currentAddr = nil

	var amount btcutil.Amount
	var unspent []btcjson.TransactionInput
	var err0 error

	// We will go through our addresses and skip addresses without a balance
	for currentAddr == nil {

		currentAddr    = b.sourceAdrs[b.srcIndex] 	// Get the current Address
		currentAddrTxt = b.sources[b.srcIndex] 		// Keep text of the Address
													// Log it for debugging
		log.Print("source: ", currentAddrTxt, " index: ", b.srcIndex)
													// Increment to the next Address
		b.srcIndex = (b.srcIndex + 1) % len(b.sourceAdrs)

		amount, unspent, err0 = b.ComputeBalance(currentAddr)
		if err0 != nil {
			log.Print("Error computing the balance")
			return
		}
		// check if amount is < .0005.  amount is in satoshis...
		if amount < 50000 {
			currentAddr = nil
		}
	}

	fee, err1 := btcutil.NewAmount(.0005)
	if err1 != nil {
		log.Print("Error create a new amount")
		return
	}

	change := amount - fee

	log.Print("Amount at the address:  ", amount)
	log.Print("Change after the trans: ", change)
	log.Print("Change+fee:             ", change+fee)
	log.Print("unspent: ", unspent)

	builder := btcscript.NewScriptBuilder()
	builder.AddOp(btcscript.OP_RETURN)
	builder.AddData(hash)
	opReturn := builder.Script()
	disasm, err := btcscript.DisasmString(opReturn)
	
	// Create a public key script that pays to the address.
	changeS, err := btcscript.PayToAddrScript(*currentAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	
	disasm, err = btcscript.DisasmString(changeS)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf ("Op_Return Hex:      %x\n", opReturn)
	log.Println("Op_Return:          ", disasm)	
	log.Printf ("Change Hex:         %x\n", changeS)
	log.Println("Change Disassembly: ", disasm)

	tx := btcwire.NewMsgTx()

	txOut := btcwire.NewTxOut(0, opReturn)
	tx.AddTxOut(txOut)
	txOut = btcwire.NewTxOut(int64(amount),changeS)
	tx.AddTxOut(txOut)

	

	return
}

//
// newBlock hashes the current LastHash into the Bitcoin Blockchain 5 minutes after
// the previous block. (If a block is signed quicker than 5 minutes, then the second
// block is ignored.)
//
func (b *Btc) newBlock(hash *btcwire.ShaHash, height int32) {

	log.Printf("Block connected: %v (%d)", hash, height)

}

