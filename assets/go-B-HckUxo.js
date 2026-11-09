import{d as e}from"./index-BGcN2egD.js";import{t}from"./jsx-runtime-PcnOhc9i.js";import{n}from"./lib-BZKU9R6Y.js";function r(r){let i={a:`a`,code:`code`,h2:`h2`,p:`p`,pre:`pre`,span:`span`,...n(),...r.components};return t(e,{children:[t(e,{children:t(i.pre,{className:`shiki shiki-themes vitesse-light vitesse-dark`,style:{"--shiki-light":`#393a34`,"--shiki-dark":`#dbd7caee`,"--shiki-light-bg":`#ffffff`,"--shiki-dark-bg":`#121212`},tabIndex:`0`,children:t(i.code,{children:t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#59873A`,"--shiki-dark":`#80A665`},children:`go`}),t(i.span,{style:{"--shiki-light":`#B56959`,"--shiki-dark":`#C98A7D`},children:` get`}),t(i.span,{style:{"--shiki-light":`#B56959`,"--shiki-dark":`#C98A7D`},children:` github.com/myzonerocks/gossmark/sdk/go`})]})})})}),`
`,t(i.h2,{id:`signing`,children:t(i.a,{href:`#signing`,children:`Signing`})}),`
`,t(i.pre,{children:t(i.code,{className:`language-go`,children:`signed, err := gossmark.Sign(seed, credential)
`})}),`
`,t(i.h2,{id:`verifying`,children:t(i.a,{href:`#verifying`,children:`Verifying`})}),`
`,t(i.pre,{children:t(i.code,{className:`language-go`,children:`badge, err := gossmark.VerifyDirect(signed, roots, revoked, now)
badge, err = gossmark.VerifyStaff(staff, capability, roots, revoked, now)
`})}),`
`,t(i.p,{children:`There's also a general entry point when your code already knows which shape
it has:`}),`
`,t(i.pre,{children:t(i.code,{className:`language-go`,children:`badge, err := gossmark.Verify(/* ... */)
`})}),`
`,t(i.h2,{id:`types`,children:t(i.a,{href:`#types`,children:`Types`})}),`
`,t(i.pre,{children:t(i.code,{className:`language-go`,children:`type Badge struct { /* kind, subject, category, issuedAt, expiresAt, issuer, via */ }
type Subject struct { /* chain, address */ }
type Credential struct{}
type Signed struct{}
type Roots struct{}
type Revoked struct{}
`})}),`
`,t(i.h2,{id:`wire-helpers`,children:t(i.a,{href:`#wire-helpers`,children:`Wire helpers`})}),`
`,t(i.pre,{children:t(i.code,{className:`language-go`,children:`gossmark.PutSigned(buf, signed)
signed, rest := gossmark.TakeSigned(buf)
gossmark.PutSnapshot(buf, snapshot)
n := gossmark.SnapshotLen(snapshot)
`})}),`
`,t(i.p,{children:`These are for writing credentials into a buffer you already own, which is
what a service doing many checks per request wants.`}),`
`,t(i.h2,{id:`revocation`,children:t(i.a,{href:`#revocation`,children:`Revocation`})}),`
`,t(i.pre,{children:t(i.code,{className:`language-go`,children:`snapshot, err := gossmark.SignSnapshot(seed, seq, issuedAt, ids)
ids, seq, issuedAt, err := gossmark.VerifySnapshot(snapshot, roots, heldSeq)
`})})]})}function i(e={}){let{wrapper:i}={...n(),...e.components};return i?t(i,{...e,children:t(r,{...e})}):r(e)}export{i as default};
//# sourceMappingURL=go-B-HckUxo.js.map