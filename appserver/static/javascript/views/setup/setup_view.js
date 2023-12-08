"use strict" ;

define(["backbone", "jquery", "splunkjs/splunk"], function(Backbone, jquery, splunk_js_sdk) {
    var View = Backbone.View.extend({
        // -----------------------------------------------------------------
        // Backbon Functions, These are specific to the Backbone library
        // -----------------------------------------------------------------
        initialize: function initialize() {
            Backbone.View.prototype.initialize.apply(this, arguments) ;
        },

        render: function() {
            this.el.innerHTML = "Let's start!" ;

            return this ;
        },
    }) ;

    return View ;
}) ;
