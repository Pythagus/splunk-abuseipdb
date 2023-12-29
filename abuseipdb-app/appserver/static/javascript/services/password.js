function does_storage_password_exist(
    storage_passwords_accessor,
    username
) {
    var storage_passwords = storage_passwords_accessor.list();
    var storage_passwords_found = [];

    for (var index = 0; index < storage_passwords.length; index++) {
        var storage_password = storage_passwords[index];
        var storage_password_stanza_name = storage_password.name;
        if (storage_password_stanza_name === ":" + username + ":") {
            storage_passwords_found.push(storage_password);
        }
    }
    var does_storage_password_exist = storage_passwords_found.length > 0;

    return does_storage_password_exist;
}

function create_storage_password_stanza(
    splunk_js_sdk_service_storage_passwords,
    realm,
    username,
    value_to_encrypt,
) {
    var parent_context = this;

    return splunk_js_sdk_service_storage_passwords.create(
        {
            name: username,
            password: value_to_encrypt,
            realm: realm,
        },
        function (error_response, response) {
            // Do nothing
        },
    );
}

async function create_credentials(
    splunk_js_sdk_service,
    username,
    api_key,
) {
    // /servicesNS/<NAMESPACE_USERNAME>/<SPLUNK_APP_NAME>/storage/passwords/<REALM>%3A<USERNAME>%3A
    var realm = null;

    var storage_passwords_accessor = splunk_js_sdk_service.storagePasswords({});
    await storage_passwords_accessor.fetch();

    var does_storage_password_exist = this.does_storage_password_exist(
        storage_passwords_accessor,
        username
    );

    if (does_storage_password_exist) {
        await this.delete_storage_password(
            storage_passwords_accessor,
            username,
        );
    }
    await storage_passwords_accessor.fetch();

    await this.create_storage_password_stanza(
        storage_passwords_accessor,
        realm,
        username,
        api_key,
    );
}

function delete_storage_password(
    storage_passwords_accessor,
    username,
) {
    return storage_passwords_accessor.del(":" + username + ":");
}

export {
    does_storage_password_exist,
    create_storage_password_stanza,
    create_credentials,
    delete_storage_password,
}
