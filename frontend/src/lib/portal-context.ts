import { getPortalUser, isPortalAuthenticated } from './portal-auth';

export interface PortalContext {
    isPortal: boolean;
    orgId: string | null;
    orgName: string | null;
    orgIndustry: string | null;
    wazuhGroup: string | null;
    portalRole: string | null;
}

const NOT_PORTAL: PortalContext = {
    isPortal: false,
    orgId: null,
    orgName: null,
    orgIndustry: null,
    wazuhGroup: null,
    portalRole: null,
};

export function getPortalContext(): PortalContext {
    if (!isPortalAuthenticated()) return NOT_PORTAL;
    const user = getPortalUser();
    if (!user) return NOT_PORTAL;
    return {
        isPortal: true,
        orgId: user.orgId,
        orgName: user.orgName,
        orgIndustry: user.orgIndustry,
        wazuhGroup: user.wazuhGroup,
        portalRole: user.portalRole,
    };
}
