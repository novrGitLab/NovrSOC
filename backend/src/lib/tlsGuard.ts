// Imported immediately after dotenv/config in index.ts: restore process-wide TLS verification
// before any other module loads. See enforceTlsVerification().
import { enforceTlsVerification } from './pinnedTls';

enforceTlsVerification();
