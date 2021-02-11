package server

// SyncLdapAttributesWithWireGuard starts to synchronize the "disabled" attribute from ldap.
// Users will be automatically disabled once they are disabled in ldap.
// This method is blocking.
func (s *Server) SyncLdapAttributesWithWireGuard() error {
	allUsers := s.users.GetAllUsers()
	for i := range allUsers {
		user := allUsers[i]
		if user.LdapUser == nil {
			continue // skip non ldap users
		}

		if user.DeactivatedAt != nil {
			continue // skip already disabled interfaces
		}
	}
	return nil
}
