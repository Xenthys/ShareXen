# ShareXen

ShareXen is an API, which is really just another ShareX custom uploader PHP script, but done right. It requires at least PHP 7.0 to run, along with the cURL extension if you plan to use Discord webhooks for logging requests. No database is required.

This API returns strict JSON results. You can easily parse its answers within your own scripts.

If you have any problem setting this up, you can ask for help on [Discord](https://discordapp.com/invite/bn) directly.

## Features

* File uploads (who would've guessed)
* File rename / deletion
* Secure deletion URLs
* Multi-user support
* Permission system
* Discord webhooks

Please note that some features (such as renaming a file) can't be used from ShareX directly, and are solely meant to be called by other scripts or programs. If you need ideas, go integrate this API into a Discord bot, which could ease management in case you plan to host it for quite a few users.

## Installing the API

1. Download the `script.php` file from this repository.
2. Open it with a text editor, and edit the configuration to your needs.
3. Upload it to your webhost by any means, using whichever filename you want.

Files will be uploaded next to the script, in the same folder.

## Using the API with ShareX

Download the `ShareXen.sxcu` file from this repository and double-click it.  
If you can't open it for whatever reason, follow that procedure:

1. Open ShareX, click on `Destinations` then `Destination settings…`.
2. Scroll to the bottom of the list and click on `Custom uploaders`.
3. Click the `Import` dropdown menu, and import the uploader file.

You will need to edit the `Request URL` field to match your own domain name and script path, along with the `auth_token` argument value that must contain a valid user token previously defined within the API itself.

## Parameters and results

The form shall be encoded as `multipart/form-data`, with the file form name of `image` when calling the `upload` endpoint. The file must therefore be in binary format, not base64-encoded.

The following string parameters are recognized by the API:

| Name            | Request     | Description                                            |
| --------------- | ----------- | ------------------------------------------------------ |
| `auth_token`    | POST only   | Authenticate for accessing restricted endpoints.       |
| `endpoint`      | GET or POST | Specify which API endpoint you're requesting.          |
| `deletion_hash` | GET or POST | Secret security key for deleting / renaming a file.    |
| `filename`      | GET or POST | For endpoints supporting / requiring a filename.       |
| `new_name`      | GET or POST | For the `rename` endpoint, file mustn't already exist. |

The following endpoints are supported:

| Name     | Supported parameters                                                                    |
| -------- | --------------------------------------------------------------------------------------- |
| `info`   | `auth_token` (user), `filename`                                                         |
| `upload` | `auth_token` (user), `image` (file), `filename`                                         |
| `delete` | `auth_token` (admin) or `deletion_hash`, `filename`                                     |
| `rename` | `auth_token` (admin) or `auth_token` (user) and `deletion_hash`, `filename`, `new_name` |

Using the `filename` parameter for the `upload` endpoint and accessing the `rename` parameter can be restricted by the configuration. Refer to the available options for more information.

The following JSON fields can be returned:

| Name             | Endpoints           | Type    | Description                                           |
| ---------------- | ------------------- | ------- | ----------------------------------------------------- |
| `api_version`    | all                 | String  | Current API version number (SemVer)                   |
| `api_source`     | all                 | String  | URL to the GitHub source repository                   |
| `endpoint`       | all                 | String  | Called API endpoint, or `unknown`                     |
| `user_id`        | all                 | Integer | Current user ID, set to `0` for unauthenticated users |
| `status`         | all                 | String  | Request status, either `success` or `error`           |
| `http_code`      | all                 | Integer | Mirror of the returned HTTP code                      |
| `filename`       | all                 | String  | Name of the file as stored on the server              |
| `execution_time` | all                 | Float   | Script execution time, in seconds                     |
| `url`            | `upload` & `rename` | String  | URL for the new file                                  |
| `deletion_hash`  | `upload` & `rename` | String  | Deletion hash for the new file                        |
| `deletion_url`   | `upload` & `rename` | String  | Full deletion URL for the new file                    |
| `method`         | `delete` & `rename` | String  | Authentication method used to call the endpoint       |
| `old_name`       | `rename`            | String  | Previous name of the file                             |
| `error`          | any                 | String  | Static error code, only sent if anything fails        |
| `debug`          | any                 | String  | Human-readable information, only for some errors      |

The `info` endpoint implements several JSON fields, which can be returned or not depending on your access level, whether you specify a filename, and whether it exists. Here is the full specification:

| Name                 | Admin | Filename    | Type             | Description                                                          |
| -------------------- | ----- | ----------- | ---------------- | -------------------------------------------------------------------- |
| `is_admin`           | No    | Irrelevant  | Boolean          | Admin status of the caller                                           |
| `file_exists`        | No    | Specified   | Boolean          | Whether the specified file exists or not                             |
| `filename`           | No    | Specified   | String           | (File must exist) Name of the file                                   |
| `filesize`           | No    | Specified   | Integer          | (File must exist) Size of the file in bytes                          |
| `uploaded_at`        | No    | Specified   | Integer          | (File must exist) File upload timestamp                              |
| `url`                | No    | Specified   | String           | (File must exist) URL to the file                                    |
| `deletion_hash`      | Yes   | Specified   | String           | (File must exist) Deletion hash of the file                          |
| `deletion_url`       | Yes   | Specified   | String           | (File must exist) Deletion URL of the file                           |
| `endpoints`          | No    | Unspecified | Array of Strings | List of supported API endpoints                                      |
| `keyspace`           | No    | Unspecified | String           | Keyspace used by the API (configuration)                             |
| `name_length`        | No    | Unspecified | Integer          | Size of random names (configuration)                                 |
| `allowed_extensions` | No    | Unspecified | Array of Strings | List of allowed file extensions (configuration)                      |
| `custom_names`       | No    | Unspecified | Boolean          | Whether custom filenames are globally allowed or not (configuration) |
| `files_count`        | No    | Unspecified | Integer          | Amount of files (matching allowed extensions) in the current folder  |
| `files`              | Yes   | Unspecified | Array of Strings | List of files (matching allowed extensions) in the current folder    |

## Limitations and security

As this script doesn't use any database, there isn't any feature such as ratelimiting, so you'll have to handle that using your webserver itself, or an intermediate service like Cloudflare.

If enabled, the Discord webhook can be called for each API call depending on your configuration. If you receive a lot of requests, you might hit the webhook ratelimit, which cannot be handled by this script and will therefore be ignored.

As a security measure, this script doesn't accept files that aren't recognized as images or videos, based on their mime type. That can be modified, but here again, do it at your own risk, I won't support you there.

Deletion hashes are only as secure as your `DELETION_SALT` is. Make sure to have a **very random** string there containing basically any character you want, and of course **never** share it with anyone. I can't stress this enough, as it would allow anyone having it to compute the deletion hash for any image file. Keep in mind that having to change the deletion salt means all previously generated deletion hashes will be rendered invalid. Of course, take great care of user tokens too, especially admin ones (if you have any) since they can be more destructive than deletion hashes, although you can safely update any of them without breaking any deletion hash whatsoever.

## Contributing

If you want to help improve this API or its documentation, feel free to come on [Discord](https://discordapp.com/invite/bn) to suggest modifications. You can also open a pull-request, but make sure to **sign your commits with GPG** and **respect the script's programming style**, so we can keep it as readable as possible.
