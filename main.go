package main

import (
	"errors"
	"strings"

	"github.com/realPy/hogosuru-jwtdecoder/crypto/hs256"
	"github.com/realPy/hogosuru-jwtdecoder/crypto/hs384"
	"github.com/realPy/hogosuru-jwtdecoder/crypto/hs512"
	"github.com/realPy/hogosuru-jwtdecoder/crypto/rs256"
	"github.com/realPy/hogosuru-jwtdecoder/jwt"

	"encoding/json"

	"github.com/realPy/hogosuru"
	"github.com/realPy/hogosuru/base/document"
	"github.com/realPy/hogosuru/base/event"
	"github.com/realPy/hogosuru/base/fetch"
	"github.com/realPy/hogosuru/base/htmltextareaelement"
	"github.com/realPy/hogosuru/base/node"
	"github.com/realPy/hogosuru/base/promise"
	"github.com/realPy/hogosuru/base/response"
	"github.com/realPy/hogosuru/hogosurudebug"
	"github.com/realPy/hogosuru/htmlstruct"
	"github.com/realPy/hogosuru/routing"
)

type MainWindow struct {
	TextAreaJWT     htmltextareaelement.HtmlTextAreaElement `hogosuru:"#jwttextarea"`
	TextAreaHeader  htmltextareaelement.HtmlTextAreaElement `hogosuru:"#headerjwt"`
	TextAreaPayload htmltextareaelement.HtmlTextAreaElement `hogosuru:"#payloadjwt"`
	TextAreaKey     htmltextareaelement.HtmlTextAreaElement `hogosuru:"#keyjwt"`
}

func (w *MainWindow) InitMainComponents(d document.Document) {

	w.TextAreaJWT.OnInput(func(e event.Event) {

		if v, err := w.TextAreaJWT.Value(); hogosuru.AssertErr(err) {
			parts, errs := jwt.CheckJWTParts(v)
			w.TextAreaJWT.Style_().SetProperty("background-color", "white")
			w.TextAreaHeader.Style_().SetProperty("background-color", "white")
			w.TextAreaPayload.Style_().SetProperty("background-color", "white")

			if len(errs) > 0 {
				w.TextAreaJWT.Style_().SetProperty("background-color", "yellow")
				w.TextAreaHeader.SetTextContent("")
				w.TextAreaPayload.SetTextContent("")
			}

			if len(parts) > 0 && len(parts[0]) > 0 {
				jobj := map[string]interface{}{}
				json.Unmarshal(parts[0], &jobj)
				if v, err := json.MarshalIndent(jobj, "", "    "); hogosuru.AssertErr(err) {

					w.TextAreaHeader.SetTextContent(string(v))
				}

			} else {
				w.TextAreaHeader.Style_().SetProperty("background-color", "yellow")
			}

			if len(parts) > 1 && len(parts[1]) > 0 {
				jobj := map[string]interface{}{}
				json.Unmarshal(parts[1], &jobj)
				if v, err := json.MarshalIndent(jobj, "", "    "); hogosuru.AssertErr(err) {

					w.TextAreaPayload.SetTextContent(string(v))
				}

			} else {
				w.TextAreaPayload.Style_().SetProperty("background-color", "yellow")
			}

		}

	})

	w.TextAreaKey.OnInput(func(e event.Event) {

		if v, err := w.TextAreaJWT.Value(); hogosuru.AssertErr(err) {
			parts, errs := jwt.CheckJWTParts(v)
			partundec := strings.SplitN(v, ".", 3)

			if len(errs) == 0 {
				jobj := map[string]interface{}{}
				json.Unmarshal(parts[0], &jobj)

				payload := []byte(string(partundec[0]) + "." + string(partundec[1]))
				if key, err := w.TextAreaKey.Value(); hogosuru.AssertErr(err) {

					var err error
					switch jobj["alg"] {
					case "HS256":
						err = hs256.CheckHS256(payload, parts[2], []byte(key))
					case "HS384":
						err = hs384.CheckHS384(payload, parts[2], []byte(key))
					case "HS512":
						err = hs512.CheckHS512(payload, parts[2], []byte(key))
					case "RS256":
						err = rs256.CheckRS256(payload, parts[2], []byte(key))
					default:
						err = errors.New("crypto hash not support")
					}

					if err == nil {
						w.TextAreaKey.Style_().SetProperty("background-color", "green")
					} else {
						w.TextAreaKey.Style_().SetProperty("background-color", "red")
					}
				}

			}
		}
	})
}

func (w *MainWindow) OnLoad(d document.Document, n node.Node, route string) (*promise.Promise, []routing.Rendering) {

	var ret *promise.Promise

	if f, err := fetch.New("main.html"); hogosuru.AssertErr(err) {
		textpromise, _ := f.Then(func(r response.Response) *promise.Promise {

			if promise, err := r.Text(); hogosuru.AssertErr(err) {
				return &promise
			}

			return nil

		}, nil)

		textpromise.Then(func(i interface{}) *promise.Promise {

			if element, err := d.DocumentElement(); hogosuru.AssertErr(err) {

				element.SetInnerHTML(i.(string))
				htmlstruct.Unmarshal(d, w)
				w.InitMainComponents(d)
			}
			return nil
		}, nil)

		ret = &textpromise
	}

	return ret, []routing.Rendering{}
}

func (w *MainWindow) OnEndChildsRendering() {

}
func (w *MainWindow) OnEndChildRendering(r routing.Rendering) {

}

func (w *MainWindow) Node(r routing.Rendering) node.Node {

	return node.Node{}
}

func (w *MainWindow) OnUnload() {

}

func main() {

	hogosuru.Init()
	hogosurudebug.EnableDebug()

	routing.Router().DefaultRendering(&MainWindow{})
	routing.Router().Start(routing.HASHROUTE)

	ch := make(chan struct{})
	<-ch

}
