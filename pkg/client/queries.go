package client

// GraphQL queries for Mercury API
const (
	// GENERATE_SERVICE_TOKEN is the mutation for generating a service token using client credentials
	GENERATE_SERVICE_TOKEN = `
		mutation GenerateServiceToken($input: ServiceTokenInput) {
			generateServiceToken(input: $input) {
				access_token
				scope
				token_type
				expires_in
			}
		}
	`

	// GET_REGISTERED_SERVICE_BY_CLIENT_ID is the mutation for fetching service details by client ID
	GET_REGISTERED_SERVICE_BY_CLIENT_ID = `
		mutation GetRegisteredServiceByClientId($input: GetRegisteredServiceByClientIdInput) {
			getRegisteredServiceByClientId(input: $input) {
				uuid
			}
		}
	`

	// GET_CONNECTED_ACCOUNT_BY_CONNECTION_ID fetches a Mercury connected account by its connectionId.
	// Returns provider info, email, status, and metadata (which includes OAuth tokens).
	// Required headers: x-project-token (service token), x-tenant-id, x-user-id
	GET_CONNECTED_ACCOUNT_BY_CONNECTION_ID = `
		query GetConnectedAccountByConnectionId($connectionId: String!) {
			getConnectedAccountByConnectionId(connectionId: $connectionId) {
				uuid
				provider
				external_user_id
				external_workspace_id
				email
				status
				metadata
				created_at
				updated_at
			}
		}
	`
)
