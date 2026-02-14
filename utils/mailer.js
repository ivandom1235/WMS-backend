// backend/utils/mailer.js

import { getAccessTokenSilent } from "./graphAuth.js";

async function sendTicketRegisteredEmail({
  to,
  customerName,
  ticketNumber,
  category,
  requestType,
  particulars
}) {
  const customerEmail = String(to || "").trim();
  const internalEmail = "info@wmservices.in";

  const EMAIL_USER = String(process.env.OPERATIONS_EMAIL || "").trim();
  const OPERATIONS_PHONE = String(process.env.OPERATIONS_PHONE || "").trim();

  if (!customerEmail) throw new Error("Customer email is empty");

  const accessToken = await getAccessTokenSilent();

  const subject = "Service Request Accepted – Status: Registered";

  const bodyText = `Dear ${customerName},

We are pleased to inform you that your request has been successfully received and accepted.

Service Request Details:
Service Request Number: ${ticketNumber}
Category: ${category || "-"}
Request Type: ${requestType || "-"}
Particulars: ${particulars|| "-"}


Current Status: Registered

Please retain the above service request number for future reference and status tracking. You may use this number when contacting our support team or while checking updates on the service portal.

Our team will review your request and take the necessary action at the earliest. You will be notified in case any additional information is required.

Thank you for reaching out to us.

Warm regards,
Support Team
WM Services
${EMAIL_USER}
${OPERATIONS_PHONE}`.trim();

  const payload = {
    message: {
      subject,
      body: { contentType: "Text", content: bodyText },
      toRecipients: [
        { emailAddress: { address: customerEmail } },
        { emailAddress: { address: internalEmail } },
      ],
    },
    saveToSentItems: true,
  };

  const res = await fetch("https://graph.microsoft.com/v1.0/me/sendMail", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {}
    throw new Error(json?.error?.message || text || `sendMail failed: ${res.status}`);
  }

  return { ok: true, status: res.status };
}

async function sendTicketCompletedEmail({
  to,
  customerName,
  ticketNumber,
  category,
  requestType,
  opRemark,
  particulars,
}) {
  const customerEmail = String(to || "").trim();
  const internalEmail = "info@wmservices.in";

  const EMAIL_USER = String(process.env.OPERATIONS_EMAIL || "").trim();
  const OPERATIONS_PHONE = String(process.env.OPERATIONS_PHONE || "").trim();

  if (!customerEmail) throw new Error("Customer email is empty");

  const accessToken = await getAccessTokenSilent();

  const subject = "Service Request Completed – Status: Completed";

  const bodyText = `Dear ${customerName},

Thank you for choosing WM Services.

We are pleased to inform you that your service request has been completed successfully.

Service Request Details:
Service Request Number: ${ticketNumber}
Category: ${category || "-"}
Request Type: ${requestType || "-"}
Particulars: ${particulars|| "-"}

Current Status: Completed
${opRemark ? `\nOperations Remark: ${opRemark}\n` : ""}

We value your feedback and would appreciate if you could take a few moments to share your experience with us by clicking the link below:
https://g.co/kgs/xk6heUg

If you have any questions or need further assistance, please reply to this email or contact our support team.

Warm regards,
Support Team
WM Services
${EMAIL_USER}
${OPERATIONS_PHONE}`.trim();

  const payload = {
    message: {
      subject,
      body: { contentType: "Text", content: bodyText },
      toRecipients: [
        { emailAddress: { address: customerEmail } },
        { emailAddress: { address: internalEmail } },
      ],
    },
    saveToSentItems: true,
  };

  const res = await fetch("https://graph.microsoft.com/v1.0/me/sendMail", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {}
    throw new Error(json?.error?.message || text || `sendMail failed: ${res.status}`);
  }

  return { ok: true, status: res.status };
}

export {
  sendTicketRegisteredEmail,
  sendTicketCompletedEmail,
};
