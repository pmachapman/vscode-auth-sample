import { AUTH_TYPE, Auth0AuthenticationProvider } from './auth0AuthenticationProvider';
import * as vscode from 'vscode';

export async function activate(context: vscode.ExtensionContext) {
	const subscriptions = context.subscriptions;
	// See https://github.com/sillsdev/web-xforge/blob/master/src/SIL.XForge.Scripture/ClientApp/src/xforge-common/auth.service.ts#L45
	const scopes = ['openid', 'profile', 'email', 'sf_data', 'offline_access'];

	subscriptions.push(
		vscode.commands.registerCommand('vscode-auth0-authprovider.signIn', async () => {
			const session = await vscode.authentication.getSession("auth0", scopes, { createIfNone: true });
			console.log(session);
		})
	);

	subscriptions.push(
		new Auth0AuthenticationProvider(context)
	);

	getAuth0Session();

	subscriptions.push(
		vscode.authentication.onDidChangeSessions(async e => {
			console.log(e);

			if (e.provider.id === AUTH_TYPE) {
				getSession();
			} else if (e.provider.id === "auth0") {
				getAuth0Session();
			}
		})
	);
}

const getAuth0Session = async () => {
	const session = await vscode.authentication.getSession("auth0", ['profile'], { createIfNone: false });
	// session.accessToken will have your JWT access token.
	// This will be run on re-open
	if (session) {
		vscode.window.showInformationMessage(`Welcome back ${session.account.label}`);
	}
};

const getSession = async () => {
	const session = await vscode.authentication.getSession(AUTH_TYPE, [], { createIfNone: false });
	// session.accessToken will have your JWT access token.
	// This will be run on login
	if (session) {
		vscode.window.showInformationMessage(`Welcome back ${session.account.label}`);
	}
};

// this method is called when your extension is deactivated
export function deactivate() {}