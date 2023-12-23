"use strict" ;

import * as Setup from '../services/setup.js'
import * as Password from '../services/password.js'
import * as Configuration from '../services/configuration.js'

const APP_NAME = "abuseipdb-app" ;
const ABUSEIPDB_CONF = "abuseipdb" ;

define(["backbone", "jquery", "splunkjs/splunk"], function(Backbone, jquery, splunk_js_sdk) {
    var View = Backbone.View.extend({
        // -----------------------------------------------------------------
        // Backbon Functions, These are specific to the Backbone library
        // -----------------------------------------------------------------
        initialize: function initialize() {
            Backbone.View.prototype.initialize.apply(this, arguments) ;

            // Configure the click event listener.
            jquery("button[name='save_button']").click(() => this.trigger_setup()) ;
            jquery("button[name='reload_button']").click(() => this.trigger_reload()) ;

            // Let's start!
            console.log("App is ready") ;
        },

        trigger_reload: function trigger_reload() {
            Setup.redirect_to_splunk_app_homepage(APP_NAME) ;
        },

        trigger_setup: function trigger_setup() {
            console.log("Updating app...") ;

            // Reset the error display.
            this.display_error_output([]) ;

            var param = {
                token: null,
            }

            // Get the AbuseIPDB token.
            param.token = jquery('#abuseipdb_token').val().trim() ;

            // Finally perform the config update.
            this.perform_setup(splunk_js_sdk, param) ;
        },

        perform_setup: async function perform_setup(splunk_js_sdk, param) {
            try {
                const splunk_service = Setup.create_splunk_js_sdk_service(splunk_js_sdk, {
                    owner: "nobody",
                    app: APP_NAME,
                    sharing: "app",
                }) ;

                // Setting up abuseipdb.conf
                //await Configuration.update_configuration_file(splunk_service, ABUSEIPDB_CONF, "stanza", {}) ;

                // Setting up savedsearches.conf
                //await Configuration.update_configuration_file(splunk_service, Splunk.SAVEDSEARCHES_CONF, "stanza", {}) ;

                // Setting up macros.conf
                //await Configuration.update_configuration_file(splunk_service, Splunk.MACROS_CONF, "stanza", {}) ;

                // Save credentials in passwords conf
                console.log("Storing credentials for [AbuseIPDB]") ;
                await Password.create_credentials(splunk_service, APP_NAME, param.token) ;

                // Completes the setup, by access the app.conf's [install]
                // stanza and then setting the `is_configured` to true
                await Setup.complete_setup(splunk_service) ;

                // Reloads the splunk app so that splunk is aware of the
                // updates made to the file system
                await Setup.reload_splunk_app(splunk_service, APP_NAME) ;

                // Redirect to the Splunk Search home page
                // This is making 'reload_splunk_app' function crashing (the server conf is not
                // reloaded). So, I replaced this with a button to reload, waiting for a bug-correction.
                //Setup.redirect_to_splunk_app_homepage(APP_NAME) ;
                jquery("button[name='reload_button']").css({'display': 'block'}) ;
            } catch(error) {
                // This could be better error catching.
                // Usually, error output that is ONLY relevant to the user
                // should be displayed. This will return output that the
                // user does not understand, causing them to be confused.
                console.error(error)
                var error_messages_to_display = [];
                if (
                    error !== null &&
                    typeof error === "object" &&
                    error.hasOwnProperty("responseText")
                ) {
                    var response_object = JSON.parse(error.responseText);
                    error_messages_to_display = this.extract_error_messages(
                        response_object.messages,
                    );
                } else {
                    // Assumed to be string
                    error_messages_to_display.push(error);
                }

                this.display_error_output(error_messages_to_display);
            }
        },

        extract_error_messages: function extract_error_messages(error_messages) {
            // A helper function to extract error messages
            var error_messages_to_display = [];
            for (var index = 0; index < error_messages.length; index++) {
                var error_message = error_messages[index];
                var error_message_to_display =
                    error_message.type + ": " + error_message.text;
                error_messages_to_display.push(error_message_to_display);
            }

            return error_messages_to_display;
        },

        display_error_output: function display_error_output(error_messages) {
            // Hides the element if no messages, shows if any messages exist
            var did_error_messages_occur = error_messages.length > 0;
    
            var error_output_element = jquery("#errors") ; 
    
            if (did_error_messages_occur) {
                var new_error = document.createElement("ul")
                for (var index = 0; index < error_messages.length; index++) {
                    var error_li = document.createElement("li")
                    error_li.innerText = error_messages[index];
                    new_error.append(error_li)
                }
    
                error_output_element.empty()
                error_output_element.append(new_error)
                error_output_element.stop();
                error_output_element.fadeIn();
            } else {
                error_output_element.stop();
                error_output_element.fadeOut({
                    complete: function () {
                        error_output_element.html("");
                    },
                });
            }
        },
    }) ;

    return View ;
}) ;
