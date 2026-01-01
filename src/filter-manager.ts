/**
 * Filter Manager for Gmail MCP Server (Read-Only)
 * Provides read-only filter listing functionality
 */

// Type definitions for Gmail API filters (for reading filter data)
export interface GmailFilterCriteria {
    from?: string;
    to?: string;
    subject?: string;
    query?: string;
    negatedQuery?: string;
    hasAttachment?: boolean;
    excludeChats?: boolean;
    size?: number;
    sizeComparison?: 'unspecified' | 'smaller' | 'larger';
}

export interface GmailFilterAction {
    addLabelIds?: string[];
    removeLabelIds?: string[];
    forward?: string;
}

export interface GmailFilter {
    id?: string;
    criteria: GmailFilterCriteria;
    action: GmailFilterAction;
}

/**
 * Lists all Gmail filters
 * @param gmail - Gmail API instance
 * @returns Array of all filters
 */
export async function listFilters(gmail: any) {
    try {
        const response = await gmail.users.settings.filters.list({
            userId: 'me',
        });

        const filters = response.data.filters || [];

        return {
            filters,
            count: filters.length
        };
    } catch (error: any) {
        throw new Error(`Failed to list filters: ${error.message}`);
    }
}

/**
 * Gets a specific Gmail filter by ID
 * @param gmail - Gmail API instance
 * @param filterId - ID of the filter to retrieve
 * @returns The filter details
 */
export async function getFilter(gmail: any, filterId: string) {
    try {
        const response = await gmail.users.settings.filters.get({
            userId: 'me',
            id: filterId,
        });

        return response.data;
    } catch (error: any) {
        if (error.code === 404) {
            throw new Error(`Filter with ID "${filterId}" not found.`);
        }
        throw new Error(`Failed to get filter: ${error.message}`);
    }
}
