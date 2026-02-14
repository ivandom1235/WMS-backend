import { sendTicketCompletedEmail } from "../utils/mailer.js";
import { pool } from "../db.js";

const ALLOWED = new Set([
  "registered",
  "in_progress",
  "delayed",
  "completed",
  "resolved",
]);

export async function updateTicketStatusAndRemark(req, res) {
  try {
    const ticketNumber = String(req.params.ticketNumber || "").trim();
    const status = String(req.body?.status || "").trim().toLowerCase();

    const receiptNo =
      req.body?.receiptNo == null ? null : String(req.body.receiptNo).trim();

    const opRemarks =
      req.body?.opRemarks == null ? null : String(req.body.opRemarks).trim();

    if (!ticketNumber)
      return res.status(400).json({ message: "ticketNumber missing" });

    if (!ALLOWED.has(status))
      return res.status(400).json({ message: "invalid status" });

    if (status === "completed") {
      if (!receiptNo)
        return res.status(400).json({ message: "Receipt No required" });

      if (!opRemarks)
        return res.status(400).json({ message: "OP Remarks required" });
    }

    // Load previous data
    const [beforeRows] = await pool.query(
      `SELECT ticket_number, customer_name, customer_email_id,
              category, request_type, status
       FROM tickets
       WHERE ticket_number = ?
       LIMIT 1`,
      [ticketNumber]
    );

    if (!beforeRows.length)
      return res.status(404).json({ message: "ticket not found" });

    const before = beforeRows[0];
    const prevStatus = String(before.status || "").toLowerCase();

    // Update DB
    await pool.query(
      `UPDATE tickets
       SET status = ?,
           remark = COALESCE(?, remark),
           OP_remarks = COALESCE(?, OP_remarks)
       WHERE ticket_number = ?`,
      [status, receiptNo, opRemarks, ticketNumber]
    );

    const [rows] = await pool.query(
      `SELECT *
       FROM tickets
       WHERE ticket_number = ?
       LIMIT 1`,
      [ticketNumber]
    );

    const ticket = rows?.[0];

    // Send email ONLY if newly completed
    if (status === "completed" && prevStatus !== "completed") {
      try {
        await sendTicketCompletedEmail({
          to: before.customer_email_id,
          customerName: before.customer_name,
          ticketNumber: before.ticket_number,
          category: before.category,
          requestType: before.request_type,
          opRemark: opRemarks, // ✅ ONLY OP REMARK GOES
          particulars: ticket.particulars || "-",
        });
      } catch (mailErr) {
        console.error("MAIL FAILED:", mailErr?.message || mailErr);
      }
    }

    return res.json({ ok: true, ticket });
  } catch (e) {
    console.error("updateTicketStatusAndRemark ERROR:", e);
    return res.status(500).json({ message: "Failed to update status." });
  }
}
