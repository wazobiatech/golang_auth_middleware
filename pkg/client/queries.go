package client

// GraphQL queries
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
)