/**
 * Label Manager for Gmail MCP Server (Read-Only)
 * Provides read-only label listing functionality
 */

// Type definitions for Gmail API labels
export interface GmailLabel {
    id: string;
    name: string;
    type?: string;
    messageListVisibility?: string;
    labelListVisibility?: string;
    messagesTotal?: number;
    messagesUnread?: number;
    color?: {
        textColor?: string;
        backgroundColor?: string;
    };
}

/**
 * Gets a detailed list of all Gmail labels
 * @param gmail - Gmail API instance
 * @returns Object containing system and user labels
 */
export async function listLabels(gmail: any) {
    try {
        const response = await gmail.users.labels.list({
            userId: 'me',
        });

        const labels = response.data.labels || [];

        // Group labels by type for better organization
        const systemLabels = labels.filter((label: GmailLabel) => label.type === 'system');
        const userLabels = labels.filter((label: GmailLabel) => label.type === 'user');

        return {
            all: labels,
            system: systemLabels,
            user: userLabels,
            count: {
                total: labels.length,
                system: systemLabels.length,
                user: userLabels.length
            }
        };
    } catch (error: any) {
        throw new Error(`Failed to list labels: ${error.message}`);
    }
}

/**
 * Finds a label by name
 * @param gmail - Gmail API instance
 * @param labelName - Name of the label to find
 * @returns The found label or null if not found
 */
export async function findLabelByName(gmail: any, labelName: string) {
    try {
        const labelsResponse = await listLabels(gmail);
        const allLabels = labelsResponse.all;

        // Case-insensitive match
        const foundLabel = allLabels.find(
            (label: GmailLabel) => label.name.toLowerCase() === labelName.toLowerCase()
        );

        return foundLabel || null;
    } catch (error: any) {
        throw new Error(`Failed to find label: ${error.message}`);
    }
}
