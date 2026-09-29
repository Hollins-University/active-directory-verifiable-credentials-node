// tap.js
// Issues a Microsoft Entra Temporary Access Pass (TAP) after a verified
// Verified ID presentation. Fails closed: any unexpected result means no TAP.

const msal = require('@azure/msal-node');

const GRAPH = 'https://graph.microsoft.com/v1.0';

const settings = {
  tenantId: process.env.TENANT_ID || process.env.azTenantId,
  clientId: process.env.CLIENT_ID || process.env.azClientId,
  clientSecret: process.env.CLIENT_SECRET || process.env.azClientSecret,
  issuerDid: process.env.ISSUER_AUTHORITY || process.env.DidAuthority,
  credentialType: process.env.CREDENTIAL_TYPE || process.env.CredentialType,
  minFaceMatch: Number(process.env.matchConfidenceThreshold || 70),
  lifetimeMinutes: Number(process.env.TAP_LIFETIME_MINUTES || 60),
  blockGroupId: process.env.TAP_BLOCK_GROUP_ID || ''
};

// A refusal is a normal "no" with a message that is safe to show the user.
class Refusal extends Error {}

const cca = new msal.ConfidentialClientApplication({
  auth: {
    clientId: settings.clientId,
    authority: `https://login.microsoftonline.com/${settings.tenantId}`,
    clientSecret: settings.clientSecret
  }
});

async function graph(method, path, body) {
  const token = await cca.acquireTokenByClientCredential({
    scopes: ['https://graph.microsoft.com/.default']
  });
  const res = await fetch(GRAPH + path, {
    method,
    headers: {
      Authorization: `Bearer ${token.accessToken}`,
      'Content-Type': 'application/json',
      'Accept-Language': 'en-US'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const msg = (data && data.error && data.error.message) || res.statusText;
    throw new Error(`Graph ${method} ${path.split('?')[0]} failed (${res.status}): ${msg}`);
  }
  return data;
}

function audit(event, details) {
  // Never pass the TAP value into this function.
  console.log(JSON.stringify({ event, time: new Date().toISOString(), ...details }));
}

// Check the callback payload ourselves, even though the service validated it.
function checkPresentation(p) {
  if (!p || p.requestStatus !== 'presentation_verified') {
    throw new Refusal('The credential was not verified.');
  }
  const vc = p.verifiedCredentialsData && p.verifiedCredentialsData[0];
  if (!vc) throw new Refusal('No credential was presented.');
  if (vc.issuer !== settings.issuerDid) throw new Refusal('This credential was not issued by Hollins.');
  if (!Array.isArray(vc.type) || !vc.type.includes(settings.credentialType)) {
    throw new Refusal('This credential type cannot be used to get a pass.');
  }
  if (!vc.credentialState || vc.credentialState.revocationStatus !== 'VALID') {
    throw new Refusal('This credential has been revoked.');
  }
  const score = vc.faceCheck && vc.faceCheck.matchConfidenceScore;
  if (typeof score !== 'number' || score < settings.minFaceMatch) {
    throw new Refusal('Face Check did not pass. Please try again or contact the help desk.');
  }
  const upn = vc.claims && vc.claims.revocationId;
  if (!upn) throw new Refusal('The credential is missing the account identifier.');
  return { vc, upn, score };
}

// Blocks anyone with an active or PIM-eligible directory role (directly
// assigned), plus members of an optional exclusion group.
async function assertNotPrivileged(userId) {
  const filter = encodeURIComponent(`principalId eq '${userId}'`);
  const active = await graph('GET', `/roleManagement/directory/roleAssignments?$filter=${filter}&$select=id`);
  const eligible = await graph('GET', `/roleManagement/directory/roleEligibilitySchedules?$filter=${filter}&$select=id`);
  if (active.value.length || eligible.value.length) {
    throw new Refusal('Accounts with admin roles cannot use self-service. Please contact the help desk.');
  }
  if (settings.blockGroupId) {
    const r = await graph('POST', `/users/${userId}/checkMemberGroups`, { groupIds: [settings.blockGroupId] });
    if (r.value.length) {
      throw new Refusal('This account cannot use self-service. Please contact the help desk.');
    }
  }
}

async function issueTap(presentation) {
  const { vc, upn, score } = checkPresentation(presentation);

  const user = await graph(
    'GET',
    `/users/${encodeURIComponent(upn)}?$select=id,userPrincipalName,mail,accountEnabled`
  );
  if (!user.accountEnabled) throw new Refusal('This account is disabled.');
  const claimMail = (vc.claims.mail || '').toLowerCase();
  if (claimMail && user.mail && claimMail !== user.mail.toLowerCase()) {
    throw new Refusal('The credential does not match the account. Please contact the help desk.');
  }

  await assertNotPrivileged(user.id);

  // A user can hold only one TAP, so remove any existing one first.
  const base = `/users/${user.id}/authentication/temporaryAccessPassMethods`;
  const existing = await graph('GET', base);
  for (const m of existing.value) {
    await graph('DELETE', `${base}/${m.id}`);
  }

  const tap = await graph('POST', base, {
    lifetimeInMinutes: settings.lifetimeMinutes,
    isUsableOnce: true
  });

  audit('tap_issued', {
    userId: user.id,
    requestId: presentation.requestId,
    faceMatch: score,
    lifetimeMinutes: tap.lifetimeInMinutes,
    replacedExisting: existing.value.length > 0
  });

  return {
    temporaryAccessPass: tap.temporaryAccessPass,
    lifetimeInMinutes: tap.lifetimeInMinutes,
    userPrincipalName: user.userPrincipalName
  };
}

module.exports = { issueTap, Refusal, audit };
