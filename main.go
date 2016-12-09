package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/gommon/log"
	elastigo "github.com/mattbaird/elastigo/lib"
)

// http://tools.ietf.org/html/rfc6962#page-9

const (
	Version                                    = 0
	SignatureTypeCertificateTimestamp          = 0
	SignatureTypeTreeHash                      = 1
	LeafTypeTimeStamped               LeafType = 0
	LogEntryTypeX509                           = 0
	LogEntryTypePreCert                        = 1
)

type Client struct {
	Client  *http.Client
	BaseURL *url.URL
}

type LeafType uint32

type LogEntryType uint32

type Entry struct {
	ExtraData string `json:"extra_data"`
	LeafInput string `json:"leaf_input"`
}

type MerkleLeaf struct {
	Version  uint32
	LeafType LeafType
	Entry    TimestampedEntry //interface{}
}

type TimestampedEntry struct {
	Timestamp time.Time
	EntryType LogEntryType

	Certificate *x509.Certificate
}

func (ml *MerkleLeaf) UnmarshalBinary(data []byte) error {
	ml.Version = uint32(data[0])
	ml.LeafType = LeafType(data[1])

	te := TimestampedEntry{}
	if err := te.UnmarshalBinary(data[2:]); err != nil {
		return err
	}

	ml.Entry = te
	return nil
}

func (te *TimestampedEntry) UnmarshalBinary(data []byte) error {
	te.Timestamp = time.Unix(int64(binary.BigEndian.Uint64(data[0:8]))/1000, 0)
	te.EntryType = LogEntryType(binary.BigEndian.Uint16(data[8:10]))

	switch te.EntryType {
	case LogEntryTypeX509:
		size := int16(binary.BigEndian.Uint16(data[11:13]))

		if cert, err := x509.ParseCertificate(data[13 : 13+size]); err != nil {
			return err
		} else {
			te.Certificate = cert
		}
	case LogEntryTypePreCert:

	}

	return nil
}

func New(u string) (*Client, error) {
	baseURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client:  http.DefaultClient,
		BaseURL: baseURL,
	}, nil
}

func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	rel, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	u := c.BaseURL.ResolveReference(rel)

	var buf io.Reader
	if body == nil {
	} else if v, ok := body.(io.Reader); ok {
		buf = v
	} else if v, ok := body.([]interface{}); ok {
		buf = new(bytes.Buffer)
		if err := json.NewEncoder(buf.(io.ReadWriter)).Encode(v); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("not supported type: %s", reflect.TypeOf(body))
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "text/json; charset=UTF-8")
	req.Header.Add("Accept", "text/json")
	return req, nil
}

func (wd *Client) do(req *http.Request, v interface{}) error {
	if b, err := httputil.DumpRequest(req, true); err == nil {
		log.Debug(string(b))
	}

	resp, err := wd.Client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if b, err := httputil.DumpResponse(resp, true); err == nil {
		log.Debug(string(b))
	}

	var r io.Reader = resp.Body

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < 300 {
	} else if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("Not found")
	} else {
		var err struct {
			ErrorMessage string `json:"error_message"`
			Success      bool   `json:"success"`
		}

		json.NewDecoder(r).Decode(&err)
		return fmt.Errorf("Statuscode: %d: %s", resp.StatusCode, err.ErrorMessage)
	}

	return json.NewDecoder(r).Decode(&v)
}

func (wd *Client) Do(req *http.Request, v interface{}) error {
	return wd.do(req, v)
}

func (c *Client) GetRoots() error {
	// ct/v1/get-roots
	return fmt.Errorf("Not implemented")
}

func (c *Client) GetEntryAndProof() error {
	// ct/v1/get-entry-and-proof
	return fmt.Errorf("Not implemented")
}

// ct/v1/add-chain
// ct/v1/add-pre-chain
// ct/v1/get-sth
// ct/v1/get-sth-consistency
// ct/v1/get-proof-by-hash

type getEntriesResponse struct {
	Entries []Entry `json:"entries"`
}

func (c *Client) GetEntries(start, end int) ([]Entry, error) {
	var response getEntriesResponse

	if req, err := c.NewRequest("GET", fmt.Sprintf("ct/v1/get-entries?start=%d&end=%d", start, end), nil); err != nil {
		return nil, err
	} else if err := c.Do(req, &response); err != nil {
		return nil, err
	} else if len(response.Entries) == 0 { //response.Success == false {
		return nil, nil
	}

	return response.Entries, nil
}

type Name struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	SerialNumber       string   `json:"organizational_unit,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
}

type Certificate struct {
	Version   int       `json:"version,omitempty"`
	Issuer    Name      `json:"issuer,omitempty"`
	Subject   Name      `json:"subject,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	// Subject Alternate Name values
	DNSNames       []string `json:"dns_names,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	IPAddresses    []net.IP `json:"ip_addresses,omitempty"`
}

type Document struct {
	Index       int         `json:"index"`
	Key         string      `json:"-"`
	CTURL       string      `json:"ct_url"`
	Timestamp   time.Time   `json:"issue_date"`
	Certificate Certificate `json:"certificate"`
}

func main() {
	client, err := New(os.Args[1])
	if err != nil {
		panic(err)
	}

	type Range struct {
		From int
		End  int
	}

	//rangeChan := make(chan Range)

	start, _ := strconv.Atoi(os.Args[2])
	/*
		to, _ := strconv.Atoi(os.Args[3])
	*/
	e := make(chan error)

	indexerChan := make(chan *Document)

	go func() {
		conn := elastigo.NewConn()
		conn.Domain = "127.0.0.1:9200"

		bulker := conn.NewBulkIndexerErrors(10, 20)
		bulker.Start()
		defer bulker.Stop()

		go func() {
			for eb := range bulker.ErrorChannel {
				log.Errorf("Error: %s\n", eb.Err.Error())
			}

			log.Error("Error chan stopped")
		}()

		count := 0

		log.Info("Indexer started")

		for doc := range indexerChan {
			// timestamp en index ook interessant

			// Merge(&doc.Certificate, *m.Certificate)

			// parse domain names for extension
			// ping ip adresses?
			// retrieve analytics code?

			if err := bulker.Index("ctdb", "certificate", doc.Key, "", "", nil, doc); err != nil {
				log.Errorf("Error indexing: %s", err.Error())
				continue
			}

			count++

			if count%500 == 0 {
				log.Infof("Indexed %d documents", count)
			}
		}

	}()

	done := make(chan bool)

	var wg sync.WaitGroup

	// how to stop on error chan

	go func() {
		sem := make(chan int, 10)

		i := start
		for {
			wg.Add(1)
			sem <- 1

			go func(from, end int) {
				defer func() {
					wg.Done()
					<-sem
				}()

				if entries, err := client.GetEntries(from, end); err != nil {
					e <- err
				} else {
					for j, entry := range entries {
						data, _ := base64.StdEncoding.DecodeString(entry.LeafInput)
						mtl := MerkleLeaf{}
						mtl.UnmarshalBinary(data)

						if mtl.Entry.Certificate == nil {
							continue
						}

						doc := Document{}
						doc.Key = fmt.Sprintf("%x-%x", mtl.Entry.Certificate.AuthorityKeyId, mtl.Entry.Certificate.SubjectKeyId)
						doc.Timestamp = mtl.Entry.Timestamp
						doc.CTURL = client.BaseURL.String()
						doc.Index = i + j
						Merge(&doc.Certificate, *mtl.Entry.Certificate)

						for _, name := range doc.Certificate.DNSNames {
							fmt.Fprintln(os.Stderr, name)
						}

						indexerChan <- &doc
					}
				}

			}(i, i+499)

			i += 500
		}

		wg.Wait()
		done <- true
	}()

	for {
		select {
		case err := <-e:
			fmt.Println("Error:", err.Error())
		case <-done:
			fmt.Println("done")
			return
			break
		}
	}

}
