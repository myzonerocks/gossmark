import{d as e}from"./index-BGcN2egD.js";import{t}from"./jsx-runtime-PcnOhc9i.js";import{n}from"./lib-BZKU9R6Y.js";function r(r){let i={a:`a`,h2:`h2`,p:`p`,...n(),...r.components};return t(e,{children:[t(i.p,{children:`A checkmark usually means a row somewhere says so. That works until you need
it to mean something off your server: in another app, on a device with no
signal, or to somebody who doesn't trust your database.`}),`
`,t(i.p,{children:`gossmark makes a badge a credential: signed bytes that carry their own proof.`}),`
`,t(i.h2,{id:`why-it-checks-offline`,children:t(i.a,{href:`#why-it-checks-offline`,children:`Why it checks offline`})}),`
`,t(i.p,{children:`A verifier takes three things and nothing else: the root keys it trusts, a
revocation snapshot, and the moment to check against.`}),`
`,t(i.p,{children:`It never opens a connection and never calls a clock. So the same badge,
checked on a plane, gives the same answer as it does online, and two clients
with different wall clocks can't disagree about validity by accident.`}),`
`,t(i.p,{children:`The cost is that you must hand it a snapshot. That's deliberate: freshness
becomes something your app decides and can show, instead of something the
library hides.`}),`
`,t(i.h2,{id:`why-organizations-issue-through-a-capability`,children:t(i.a,{href:`#why-organizations-issue-through-a-capability`,children:`Why organizations issue through a capability`})}),`
`,t(i.p,{children:`A newspaper should be able to badge its own journalists without your team
approving each one. Giving the newspaper a root key would let it badge
anything.`}),`
`,t(i.p,{children:`So it gets a capability: permission to issue for a scope. The scope is
checked during verification, not trusted, so an organization approved for one
category can't issue for another.`}),`
`,t(i.p,{children:`Revoking that one capability refuses every badge that flowed from it at once.`}),`
`,t(i.h2,{id:`why-the-subject-is-not-a-name`,children:t(i.a,{href:`#why-the-subject-is-not-a-name`,children:`Why the subject is not a name`})}),`
`,t(i.p,{children:`Names change. People rename themselves, organizations rebrand, handles get
transferred.`}),`
`,t(i.p,{children:`A credential's subject is a wallet-bound identifier, so none of that touches
the badge. Your product maps identifier to display name, and that mapping is
yours to change.`})]})}function i(e={}){let{wrapper:i}={...n(),...e.components};return i?t(i,{...e,children:t(r,{...e})}):r(e)}export{i as default};
//# sourceMappingURL=about-DINI2xcB.js.map