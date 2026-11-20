/**
 * The little of GitHub's REST API this Action uses. The token goes only to the API address GitHub's own runner sets
 * (GITHUB_API_URL), every answer is read as untrusted JSON, and nothing here ever follows a redirect with the token.
 */

export interface GitHubApi {
  /** The repository role of a person: `admin`, `maintain`, `write`, `triage`, `read`, or `none`. */
  roleOf(repo: string, login: string): Promise<string>;
  createPullRequest(repo: string, input: { title: string; head: string; base: string; body: string }): Promise<{ number: number; url: string }>;
  comment(repo: string, issueNumber: number, body: string): Promise<void>;
}

/** Roles that may ask for a change to be made. Anything not listed, including a role this code has never heard of, may not. */
export const WRITER_ROLES: ReadonlySet<string> = new Set(['admin', 'maintain', 'write']);

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export class RestGitHub implements GitHubApi {
  readonly #token: string;
  readonly #base: string;
  readonly #fetch: typeof fetch;

  constructor(token: string, base: string = process.env['GITHUB_API_URL'] ?? 'https://api.github.com', fetchImpl: typeof fetch = fetch) {
    if (token === '') throw new Error('There is no GitHub token.');
    this.#token = token;
    this.#base = base.replace(/\/+$/, '');
    this.#fetch = fetchImpl;
  }

  async #call(method: string, path: string, body?: unknown): Promise<unknown> {
    const response = await this.#fetch(`${this.#base}${path}`, {
      method,
      redirect: 'error',
      headers: { authorization: `Bearer ${this.#token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'haven-harness-action', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(30_000),
    });
    const text = (await response.text()).slice(0, MAX_RESPONSE_BYTES);
    if (!response.ok) throw new Error(`GitHub answered ${response.status} to ${method} ${path.split('?')[0]}.`);
    try {
      return text === '' ? {} : JSON.parse(text);
    } catch {
      throw new Error(`GitHub's answer to ${method} ${path.split('?')[0]} was not JSON.`);
    }
  }

  async roleOf(repo: string, login: string): Promise<string> {
    try {
      const answer = (await this.#call('GET', `/repos/${repo}/collaborators/${encodeURIComponent(login)}/permission`)) as Record<string, unknown>;
      const role = answer['role_name'];
      return typeof role === 'string' && /^[a-z_-]{1,40}$/.test(role) ? role : 'none';
    } catch (error) {
      // A person who is not a collaborator gets a 404. Anything else is a failure, and a failure is never a yes.
      if (error instanceof Error && /answered 404/.test(error.message)) return 'none';
      throw error;
    }
  }

  async createPullRequest(repo: string, input: { title: string; head: string; base: string; body: string }): Promise<{ number: number; url: string }> {
    const answer = (await this.#call('POST', `/repos/${repo}/pulls`, input)) as Record<string, unknown>;
    const number = answer['number'];
    const url = answer['html_url'];
    if (typeof number !== 'number' || typeof url !== 'string') throw new Error('GitHub did not say which pull request it made.');
    return { number, url };
  }

  async comment(repo: string, issueNumber: number, body: string): Promise<void> {
    await this.#call('POST', `/repos/${repo}/issues/${issueNumber}/comments`, { body });
  }
}
