# Updating ShareXen

This file contains information about breaking changes happening on major releases of ShareXen, and explains which points need to be updated in various clients relying on the API.

For migrating between minor / patch releases:
- Save your configuration somewhere.
- Download the latest release of ShareXen.
- Replace the default configuration with yours.
- Ensure you didn't miss new configuration constants.
- Backup your old version somewhere safe, in case of problem.
- Upload the script to your webserver and replace the old version.
- Make sure it works properly, else restore the old version and open an issue.

Migrating between major releases follows the same procedure, but may require you to update your API configuration. Your users may also need to update their clients in order to support the new API version, since it is very likely to introduce breaking changes. Detailed instructions for major releases migration are available below.


## From 0.x to 1.x

This shouldn't concern many people, but if you were using ShareXen before the v1.x release, the only breaking change concerns the `api_version` JSON field, which has been changed from a floating-point number to a string for more granularity. It marks the beginning of semantic versioning (see [SemVer](https://semver.org/)) usage within this project.


### API Configuration

No configuration option has been changed.


### ShareX Configuration

There is nothing to change, the ShareX custom uploader doesn't rely on the API version at all.


### General Instructions

If you had an API version check in any of your projects, you can't compare numbers anymore. Ensure you now perform [SemVer](https://semver.org/) checks.



## From 1.x to 2.x

This release enhances user-friendliness by changing the way API users and administrators are handled. A configuration option along with a few parameters have also been renamed to simpler / more logical names, in order to be more future-proof and understandable.

There is also a behavioral change within the authentication function: when an empty `token` parameter is passed or when it is equal to `change-me`, the API now rejects the request with a 403 status code and an `invalid_credentials` error instead of silently considering the request as unauthenticated. This is preferable as it means the caller effectively provided a `token` parameter in order to authenticate, which is effectively not valid for authentication.

The script file in this repository has also been renamed from `script.php` to `sharexen.php` as people will not always rename it, so better not give it a generic name by default. Also prevents random people from trying to hit generic script names on some webhosts, which is not an unseen practice.


### API Configuration

First, you will have to update USER_TOKENS to the new USERS format.

Per example, let's say this is your current configuration:
```php
define('USER_TOKENS', [
	'pleasedonotusethisasatokenthx', // Alice
	'whyareyouevenreadingthisstring', // Bob
	'ihavenoideawhyimwritingthose', // Carol
	'couldyoujustfocusonthisguide' // David
]);
```

You will have to rename the constant to USERS, and update the content as follows:
```php
define('USERS', [
	'Alice' => 'pleasedonotusethisasatokenthx',
	'Carol' => 'ihavenoideawhyimwritingthose',
	'Bob' => 'whyareyouevenreadingthisstring',
	'David' => 'couldyoujustfocusonthisguide',
]);
```

This makes it easier for finding people in the logs, and the token order doesn't matter anymore. Please note that a final comma on the last line isn't mandatory, but makes things easier in case you want to add any entry under it. It's too easy to forget a comma and get a server error, stay safe.

Then, you will have to update MAX_ADMIN_ID to the new ADMINS format.  
In the above example, Bob used to be above Carol as an instance administrator. Since that doesn't matter anymore, Bob can finally be a gentleman and let women first. :wink:

Per example, let's say you had the first two users (Alice and Bob) as administrators:
```php
define('MAX_ADMIN_ID', 2);
```

You now have to set a list of usernames that will have administrator privileges:
```php
define('ADMINS', ['Alice', 'Bob']);
```

This is more secure, way easier to handle, and you don't have to count entries positions anymore. If you don't want any administrator, you can keep the list empty or even entirely remove the definition from your configuration. If you keep the definition, do not remove the brackets.

Finally, you will have to rename the DELETION_SALT constant to SALT only. That's all!

Better be safe than sorry, here's the example. Let's say this is what you have:
```php
define('DELETION_SALT', 'randomgarbageherebutfortheloveofgoddonotusethisexampleasyourownsaltthankyou');
```

You just need to rename the constant, nothing else:
```php
define('SALT', 'randomgarbageherebutfortheloveofgoddonotusethisexampleasyourownsaltthankyou');
```

The reason this has been renamed is because the salt is used to generate "security keys" (renamed from "deletion hashes"), which can be used to control files, not only to delete them.


### ShareX Configuration

The `auth_token` parameter has been renamed to `token`.

You will have to edit your custom uploader settings:
- Go to `Destinations` → `Destination settings…` then scroll to the bottom of the list.
- Click on `Custom uploaders` then your ShareXen entry, named `ShareXen` by default.
- Click on the `auth_token` entry in the `Arguments` list, which should fill the two text fields.
- Rename `auth_token` to `token` in the first text field, then click the `Update` button.
- Close the settings window, you're all set!

As `deletion_hash` has been renamed to `key`, please keep in mind that deletion URLs in your history will have to be edited in order to work. See the general instructions below for more information.


### General Instructions

First, as the `auth_token` parameter has been renamed to `token`, you have to update the variable's name within your authentication method.

Then, any deletion URL you saved or any request you make using a security key (formerly known as a "deletion hash") has to be updated to use the `key` parameter everywhere you used to have `deletion_hash`, as the key proves you have control over the file, and doesn't only allow you to delete it under certain configurations.

Per example, let's say you have the following deletion URL:
```
https://example.com/sharexen.php?endpoint=delete&deletion_hash=3ac80636f088a271df8bcbc21343a4893c49503b639d898b73a765e052757c9e&filename=8tTp17p.png
```

You only have to search and replace `deletion_hash` to `key` in it:
```
https://example.com/sharexen.php?endpoint=delete&key=3ac80636f088a271df8bcbc21343a4893c49503b639d898b73a765e052757c9e&filename=8tTp17p.png
```

Finally, the API no longer returns a `user_id` integer field, but a `username` string field, and **only** when the request has been made by an authenticated user. That means you should no longer check if `user_id` (which doesn't exist anymore) is greater than 0 to detect if the user was properly authenticated, but instead check whether `username` is defined or not.