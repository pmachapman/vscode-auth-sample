import { authentication, AuthenticationProvider, AuthenticationProviderAuthenticationSessionsChangeEvent, AuthenticationSession, Disposable, env, EventEmitter, ExtensionContext, ProgressLocation, Uri, UriHandler, window } from "vscode";
import { v4 as uuid } from 'uuid';
import { PromiseAdapter, promiseFromEvent } from "./util";
import fetch from 'node-fetch';
import * as crypto from 'crypto';

export const AUTH_TYPE = `auth0`;
const AUTH_NAME = `Scripture Forge`;
// DEV Credentials
// NOTE: Your redirect_uri must be registered on our dev Auth0 for this to work
const AUTH0_DOMAIN = `sil-appbuilder.auth0.com`;
const CLIENT_ID = `aoAGb9Yx1H5WIsvCW6JJCteJhSa37ftH`;

// QA Credentials
// NOTE: Your redirect_uri must be registered on our QA Auth0 for this to work
// const AUTH0_DOMAIN = `dev-sillsdev.auth0.com`;
// const CLIENT_ID = `4eHLjo40mAEGFU6zUxdYjnpnC1K1Ydnj`;

// LIVE Credentials
// NOTE: Your redirect_uri must be registered on our Live Auth0 for this to work
// const AUTH0_DOMAIN = `login.languagetechnology.org`;
// const CLIENT_ID = `tY2wXn40fsL5VsPM4uIHNtU6ZUEXGeFn`;

const SESSIONS_SECRET_KEY = `${AUTH_TYPE}.sessions`;

class UriEventHandler extends EventEmitter<Uri> implements UriHandler {
	public handleUri(uri: Uri) {
		this.fire(uri);
	}
}

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
	private _sessionChangeEmitter = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>();
  private _disposable: Disposable;
  private _pendingStates: string[] = [];
  private _codeExchangePromises = new Map<string, { promise: Promise<any>; cancel: EventEmitter<void> }>();
  private _uriHandler = new UriEventHandler();
  private _verifier: Buffer = crypto.randomBytes(32);
  
  constructor(private readonly context: ExtensionContext) {
    this._disposable = Disposable.from(
      authentication.registerAuthenticationProvider(AUTH_TYPE, AUTH_NAME, this, { supportsMultipleAccounts: false }),
      window.registerUriHandler(this._uriHandler)
    );
  }

	get onDidChangeSessions() {
		return this._sessionChangeEmitter.event;
	}

  get redirectUri() {
    const publisher = this.context.extension.packageJSON.publisher;
    const name = this.context.extension.packageJSON.name;
    return `${env.uriScheme}://${publisher}.${name}`;
  }

  /**
   * Get the existing sessions
   * @param scopes 
   * @returns 
   */
  public async getSessions(scopes?: string[]): Promise<readonly AuthenticationSession[]> {
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);

    if (allSessions) {
      return JSON.parse(allSessions) as AuthenticationSession[];
    }

    return [];
  }

  /**
   * Create a new auth session
   * @param scopes 
   * @returns 
   */
  public async createSession(scopes: string[]): Promise<AuthenticationSession> {
    try {
      const token = await this.login(scopes);
      if (!token) {
        throw new Error(`Auth0 login failure`);
      }

      const userinfo: { name: string, email: string } = await this.getUserInfo(token.access_token);

      // TODO: Store token.refresh_token securely
      const session: AuthenticationSession = {
        id: uuid(),
        accessToken: token.access_token,
        account: {
          label: userinfo.name,
          id: userinfo.email
        },
        scopes: []
      };

      await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify([session]));

      this._sessionChangeEmitter.fire({ added: [session], removed: [], changed: [] });

      return session;
    } catch (e) {
      window.showErrorMessage(`Sign in failed: ${e}`);
			throw e;
    }
  }

  /**
   * Remove an existing session
   * @param sessionId 
   */
  public async removeSession(sessionId: string): Promise<void> {
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);
    if (allSessions) {
      let sessions = JSON.parse(allSessions) as AuthenticationSession[];
      const sessionIdx = sessions.findIndex(s => s.id === sessionId);
      const session = sessions[sessionIdx];
      sessions.splice(sessionIdx, 1);

      await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify(sessions));

      if (session) {
        this._sessionChangeEmitter.fire({ added: [], removed: [session], changed: [] });
      }      
    }
  }

  /**
   * Dispose the registered services
   */
	public async dispose() {
		this._disposable.dispose();
	}

  private async getAccessAndRefreshTokens(code: string) : Promise<any> {
    return await window.withProgress<string>({
			location: ProgressLocation.Notification,
			title: "Getting refresh token...",
			cancellable: true
		}, async (_, token) => {

      const searchParams = new URLSearchParams([
        ['grant_type', 'authorization_code'],
        ['client_id', CLIENT_ID],
        ['code_verifier', this.base64UrlEncode(this._verifier)],
        ['code', code],
        ['redirect_uri', this.redirectUri],
      ]);
      const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
        headers: {
          'content-type': 'application/x-www-form-urlencoded'
        },
        method: 'POST',
        body: searchParams.toString(),
      });
      return await response.json();
    });
  }

  /**
   * Log in to Auth0
   */
  private async login(scopes: string[] = []): Promise<any> {
    return await window.withProgress<string>({
			location: ProgressLocation.Notification,
			title: "Signing in to Auth0...",
			cancellable: true
		}, async (_, token) => {

      // Generate a new code verifier for PKCE
      this._verifier = crypto.randomBytes(32);

      const stateId = uuid();

      this._pendingStates.push(stateId);

      const scopeString = scopes.join(' ');

      if (!scopes.includes('openid')) {
        scopes.push('openid');
      }
      if (!scopes.includes('profile')) {
        scopes.push('profile');
      }
      if (!scopes.includes('email')) {
        scopes.push('email');
      }
      if (!scopes.includes('offline_access')) {
        scopes.push('offline_access');
      }
      if (!scopes.includes('sf_data')) {
        scopes.push('sf_data');
      }

      // Create the code challenge
      // Auth0 requires a base64url encoded sha256 hash of the base64url encoded code verifier!!!!
      const codeChallenge = this.base64UrlEncode(this.sha256(Buffer.from(this.base64UrlEncode(this._verifier), 'utf8')));

      const searchParams = new URLSearchParams([
        ['response_type', 'code'],
        ['client_id', CLIENT_ID],
        ['code_challenge', codeChallenge],
        ['code_challenge_method', 'S256'],
        ['redirect_uri', this.redirectUri],
        ['state', stateId],
        ['scope', scopes.join(' ')],
        ['prompt', 'login'],
        ['audience', 'https://scriptureforge.org/']
      ]);
      const uri = Uri.parse(`https://${AUTH0_DOMAIN}/authorize?${searchParams.toString()}`);
      await env.openExternal(uri);

      let codeExchangePromise = this._codeExchangePromises.get(scopeString);
      if (!codeExchangePromise) {
        codeExchangePromise = promiseFromEvent(this._uriHandler.event, this.handleUri());
        this._codeExchangePromises.set(scopeString, codeExchangePromise);
      }

      try {
        return await Promise.race([
          codeExchangePromise.promise,
          new Promise<string>((_, reject) => setTimeout(() => reject('Cancelled'), 60000)),
          promiseFromEvent<any, any>(token.onCancellationRequested, (_, __, reject) => { reject('User Cancelled'); }).promise
        ]);
      } finally {
        this._pendingStates = this._pendingStates.filter(n => n !== stateId);
        codeExchangePromise?.cancel.fire();
        this._codeExchangePromises.delete(scopeString);
      }
    });
  }

  /**
   * Handle the redirect to VS Code (after sign in from Auth0)
   * @param scopes 
   * @returns 
   */
  private handleUri: () => PromiseAdapter<Uri, any> = 
  () => async (uri, resolve, reject) => {
    const query = new URLSearchParams(uri.query);
    const code = query.get('code');
    if (!code) {
      reject(new Error('No code'));
      return;
    }

    // Get the access and refresh tokens
    var tokens = await this.getAccessAndRefreshTokens(code);
    // Possible Fields: 
    //
    // access_token: string
    // id_token: string
    // refresh_token: string /* NOTE: This requires the offline_access scope */
    // token_type: string
    // scope: string
    // expires_in: number

    const state = query.get('state');

    if (!tokens.access_token) {
      reject(new Error('No access token'));
      return;
    }
    if (!tokens.refresh_token) {
      reject(new Error('No refresh token'));
      return;
    }
    if (!state) {
      reject(new Error('No state'));
      return;
    }

    // Check if it is a valid auth request started by the extension
    if (!this._pendingStates.some(n => n === state)) {
      reject(new Error('State not found'));
      return;
    }

    resolve(tokens);
  };

  /**
   * Get the user info from Auth0
   * @param token 
   * @returns 
   */
  private async getUserInfo(token: string) {
    const response = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    return await response.json();
  }

  private base64UrlEncode(buffer: Buffer): string {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
  }

  private sha256(buffer: Buffer): Buffer {
    return crypto.createHash('sha256').update(buffer).digest();
  }
}