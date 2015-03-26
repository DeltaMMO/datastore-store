/*
	Copyright 2015 Palm Stone Games, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

/*
This sessionStore package provides a store implementing the gorilla session store interface
and using google datastore as its backend

This package uses the new google.golang.org/appengine import path, not the old appengine path
*/
package datastoreStore

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
)

// Session is used to load and save session data in the datastore.
type Session struct {
	Date  time.Time
	Value []byte
}

// Store -------------------------------------------------------------

// NewStore returns a new DatastoreStore.
//
// The kind argument is the kind name used to store the session data.
// If empty it will use "Session".
//
// See NewCookieStore() for a description of the other parameters.
func NewDatastoreStore(kind string, keyPairs ...[]byte) *DatastoreStore {
	if kind == "" {
		kind = "Session"
	}
	return &DatastoreStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		kind: kind,
	}
}

// Store stores sessions in the App Engine datastore.
type DatastoreStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	kind    string
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *DatastoreStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *DatastoreStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	session.Options = &(*s.Options)
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			err = s.load(r, session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *DatastoreStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.ID == "" {
		session.ID = string(base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)))
	}
	if err := s.save(r, session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// save writes encoded session.Values to datastore.
func (s *DatastoreStore) save(r *http.Request, session *sessions.Session) error {
	c := appengine.NewContext(r)
	k := datastore.NewKey(c, s.kind, session.ID, 0, nil)

	if len(session.Values) == 0 {
		return datastore.Delete(c, k)
	}

	serialized, err := serialize(session.Values)
	if err != nil {
		return err
	}
	k, err = datastore.Put(c, k, &Session{
		Date:  time.Now(),
		Value: serialized,
	})
	if err != nil {
		return err
	}
	return nil
}

// load gets a value from datastore and decodes its content into
// session.Values.
func (s *DatastoreStore) load(r *http.Request, session *sessions.Session) error {
	c := appengine.NewContext(r)
	k := datastore.NewKey(c, s.kind, session.ID, 0, nil)
	entity := Session{}
	if err := datastore.Get(c, k, &entity); err != nil {
		return err
	}
	if err := deserialize(entity.Value, &session.Values); err != nil {
		return err
	}
	return nil
}

// Serialization --------------------------------------------------------------

// serialize encodes a value using gob.
func serialize(src interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(src); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deserialize decodes a value using gob.
func deserialize(src []byte, dst interface{}) error {
	dec := gob.NewDecoder(bytes.NewBuffer(src))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
