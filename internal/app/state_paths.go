package app

import (
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/trust"
)

type commandStatePaths struct {
	StatePath     string
	TrustPaths    trust.Paths
	CandidatePath string
}

func resolveCommandStatePaths(statePath string) (commandStatePaths, error) {
	opts := state.StateAuditOptions{
		StatePath: statePath,
	}

	commsStatePath, err := state.ResolveStateDomainPath(opts, state.StateDomainCommsState)
	if err != nil {
		return commandStatePaths{}, err
	}

	trustStorePath, err := state.ResolveStateDomainPath(opts, state.StateDomainTrustStore)
	if err != nil {
		return commandStatePaths{}, err
	}

	trustHistoryPath, err := state.ResolveStateDomainPath(opts, state.StateDomainTrustHistory)
	if err != nil {
		return commandStatePaths{}, err
	}

	candidatePath, err := state.ResolveStateDomainPath(opts, state.StateDomainCandidateStore)
	if err != nil {
		return commandStatePaths{}, err
	}

	return commandStatePaths{
		StatePath: commsStatePath,
		TrustPaths: trust.Paths{
			TrustPath:  trustStorePath,
			EventsPath: trustHistoryPath,
		},
		CandidatePath: candidatePath,
	}, nil
}
