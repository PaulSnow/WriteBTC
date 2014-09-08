package main

import (
	"log"
	"writebtc"
	"time"
	"crypto/sha256"
	"encoding/hex"
	"github.com/conformal/btcec"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcnet"
	
) 

func main() {
	
	var sources  []string
	var privates []*btcec.PrivateKey	
	
	// This is our base key for our key value pairs.
    hash := []byte{ 0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80, }
    // We hash it once.
	h    := sha256.New()

	// Create all of our private/public key pairs
	for i:=0;i<10;i++ {
 		h.Reset()
    	h.Write(hash)
    	hash = h.Sum(nil)		
		p,s := btcec.PrivKeyFromBytes(btcec.S256(),hash) 
		btcadr,err := btcutil.NewAddressPubKey(s.SerializeCompressed(),  &btcnet.TestNet3Params)
		if err != nil {
		   log.Println("Error creating addresses: ",err)
		   return
		} 
		sources  = append(sources,btcadr.EncodeAddress())
		privates = append(privates,p)	
		log.Println("addr: ",btcadr.EncodeAddress())
	}  
	 
	var b *writebtc.Btc
	b = new(writebtc.Btc)
	
	err := b.Init(sources, privates)
    defer b.Shutdown()					// Give b a chance to clean up on exit.
    
    if err != nil {
       log.Println("Error initializing... ",err)
       return
    }
    
    hash = []byte{ 30,10,39,49,50,24,46,246,131,49,064,83,128,103,192,19,27,37,229,220, }
	 
	for {
		h.Reset()
    	h.Write(hash)
    	hash = h.Sum(nil)
    	s := hex.EncodeToString(hash)
		log.Println("len, hash: ",len(hash),s)
		b.RecordHash(hash)
		log.Print()
  		time.Sleep(time.Minute)
	}
	log.Println("Done!")
																																																																																																																																																																																																																																																																																										
}
