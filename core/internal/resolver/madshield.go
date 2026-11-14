package resolver

// MadShield hook: HostGuard, when set, is asked about every NAME the program is about to look
// up or connect to (not about IP addresses). An error stops the lookup or the dial. MadShield sets it to a list of
// Mozilla's hosts, so nothing else can be reached by name, whatever the settings, the server list or a dashboard
// request ask for.
var HostGuard func(host string) error

func guardHost(host string) error {
	if g := HostGuard; g != nil {
		return g(host)
	}
	return nil
}
