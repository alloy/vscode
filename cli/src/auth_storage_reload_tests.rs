/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;

#[tokio::test]
async fn credential_reloads_external_login() {
	let root = std::env::current_dir()
		.unwrap()
		.join("target")
		.join("auth-storage-reload");
	std::fs::create_dir_all(&root).unwrap();
	let directory = tempfile::Builder::new()
		.prefix("profile-")
		.tempdir_in(root)
		.unwrap();
	let paths = LauncherPaths::new_without_replacements(directory.path().to_path_buf());
	let initial = StoredCredential {
		provider: AuthProvider::Microsoft,
		access_token: "synthetic-auth-reload-a".to_string(),
		refresh_token: None,
		expires_at: None,
	};
	std::fs::write(
		paths.root().join("token.json"),
		serde_json::to_vec(&Some(seal(&initial))).unwrap(),
	)
	.unwrap();

	let reader = Auth::new(&paths, log::Logger::test());
	assert_eq!(
		reader.get_credential().await.unwrap().access_token(),
		"synthetic-auth-reload-a"
	);
	let writer = Auth::new(&paths, log::Logger::test());
	writer
		.login(
			Some(AuthProvider::Microsoft),
			Some("synthetic-auth-reload-b".to_string()),
			None,
		)
		.await
		.unwrap();
	assert_eq!(
		reader.get_credential().await.unwrap().access_token(),
		"synthetic-auth-reload-b",
		"auth-storage-reload-requires-external-credential"
	);
}
