import * as fs from 'fs';
import * as _ from '@snyk/lodash';
import * as path from 'path';
import * as pathUtil from 'path';
import { TestResult, LegacyVulnApiResult } from './legacy';
import * as snyk from '..';
import { isCI } from '../is-ci';
import * as common from './common';
import * as config from '../config';
import { Options, TestOptions } from '../types';
import { Payload, CloudConfigScan } from './types';
import { SEVERITY } from './legacy';

export async function parseCloudConfigRes(
  res: LegacyVulnApiResult,
  targetFile: string | undefined,
  projectName: any,
  severityThreshold?: SEVERITY,
): Promise<TestResult> {
  const meta = (res as any).meta || {};

  severityThreshold =
    severityThreshold === SEVERITY.LOW ? undefined : severityThreshold;

  return {
    ...res,
    targetFile,
    projectName,
    org: meta.org,
    policy: meta.policy,
    isPrivate: !meta.isPublic,
    severityThreshold,
  };
}

export async function assembleCloudConfigLocalPayloads(
  options: Options & TestOptions,
): Promise<Payload[]> {
  const payloads: Payload[] = [];
  if (!options.file) {
    return payloads;
  }
  const baseName = path.basename(options.file);
  // Forcing options.path to be a string as pathUtil requires is to be stringified
  const targetFile = options.file;
  const targetFileRelativePath = targetFile
    ? pathUtil.join(pathUtil.resolve(`${options.path}`), targetFile)
    : '';

  const fileContent = fs.readFileSync(targetFile, 'utf8');
  let body: CloudConfigScan = {
    data: {
      fileContent,
      fileType: 'yaml',
    },
    targetFile: targetFile,
    type: 'k8sconfig',
    //TODO(orka): remove policy
    policy: '', //policy && policy.toString()
    targetFileRelativePath: `${targetFileRelativePath}`, // Forcing string
    originalProjectName: baseName,
  };

  const payload: Payload = {
    method: 'POST',
    url: config.API + (options.vulnEndpoint || '/test-cloud-config'),
    json: true,
    headers: {
      'x-is-ci': isCI(),
      authorization: 'token ' + (snyk as any).api,
    },
    qs: common.assembleQueryString(options),
    body,
  };

  payloads.push(payload);
  return payloads;
}
