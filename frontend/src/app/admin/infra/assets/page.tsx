import { redirect } from 'next/navigation';

// Folded into the unified VMS inventory (Release 2 Stage 5, P28): this page showed only the raw
// Wazuh agent list, with none of the findings, risk, scan eligibility or scanning-authorisation
// data the VMS Assets page already carries for the same endpoints. Kept as a redirect so existing
// links and bookmarks still work. /client/infra/assets is unaffected — it serves the client
// portal, which has no VMS Assets equivalent.
export default function Page() {
    redirect('/admin/vms/assets?category=wazuh');
}
