import * as graphlib from '@snyk/graphlib';
import { CallGraph } from '@snyk/cli-interface/legacy/common';

import {
  REACHABLE_VULNS_SUPPORTED_PACKAGE_MANAGERS,
  SupportedPackageManagers,
} from './package-managers';
import { isFeatureFlagSupportedForOrg } from './feature-flags';
import {
  AuthFailedError,
  FeatureNotSupportedByPackageManagerError,
  UnsupportedFeatureFlagError,
} from './errors';
import { MonitorOptions, Options, TestOptions } from './types';

const featureFlag = 'reachableVulns';

export function serializeCallGraphWithMetrics(
  callGraph: CallGraph,
): {
  callGraph: any;
  nodeCount: number;
  edgeCount: number;
} {
  return {
    callGraph: graphlib.json.write(callGraph),
    nodeCount: callGraph.nodeCount(),
    edgeCount: callGraph.edgeCount(),
  };
}

export async function validatePayload(
  org: any,
  options: (Options & TestOptions) | (Options & MonitorOptions),
  packageManager?: SupportedPackageManagers,
): Promise<boolean> {
  if (
    packageManager &&
    !options.allProjects &&
    !options.yarnWorkspaces &&
    !REACHABLE_VULNS_SUPPORTED_PACKAGE_MANAGERS.includes(packageManager)
  ) {
    throw new FeatureNotSupportedByPackageManagerError(
      'Reachable vulns',
      packageManager,
    );
  }
  const reachableVulnsSupportedRes = await isFeatureFlagSupportedForOrg(
    featureFlag,
    org,
  );

  if (reachableVulnsSupportedRes.code === 401) {
    throw AuthFailedError(
      reachableVulnsSupportedRes.error,
      reachableVulnsSupportedRes.code,
    );
  }
  if (reachableVulnsSupportedRes.userMessage) {
    throw new UnsupportedFeatureFlagError(
      featureFlag,
      reachableVulnsSupportedRes.userMessage,
    );
  }
  return true;
}
