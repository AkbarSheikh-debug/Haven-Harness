import assert from 'node:assert/strict';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { projectKey, resolvePaths } from '@hn/config';

describe('paths', () => {
  it('honours HN_HOME', () => {
    assert.equal(resolvePaths({ HN_HOME: 'somewhere' }).sessions, join('somewhere', 'sessions'));
  });

  it('treats Windows drive letter case as one project', () => {
    assert.equal(projectKey('D:\\repo', 'win32'), projectKey('d:\\repo', 'win32'));
    assert.notEqual(projectKey('D:\\repo', 'win32'), projectKey('D:\\other', 'win32'));
  });
});
