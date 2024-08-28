// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null, // Holds the configuration data loaded from metrics.json
            showDetails: false, // Boolean to control visibility of detailed metric information
            header_height: 0, // Stores the height of the header element, useful for responsive design
            macroVector: null, // Stores the summarized vector representation
            vectorInstance: new Vector(), // Instance of the Vector class to manage CVSS vectors
            cvssInstance: null // Instance of the CVSS40 class to calculate scores and severities
        };
    },
    methods: {
        /**
         * Fetches and loads the configuration data from the metrics.json file.
         * Initializes the vector and CVSS instances after loading the data.
         */
        async loadConfigData() {
            try {
                const response = await fetch('./metrics.json');
                this.cvssConfigData = await response.json();
                this.resetSelected(); // Reset vector instance to default state
                this.updateCVSSInstance(); // Initialize CVSS instance with default data
            } catch (error) {
                console.error("Failed to load configuration data:", error);
            }
        },
        /**
         * Generates CSS classes for buttons based on their properties.
         * @param {boolean} isPrimary - Determines if the button is styled as primary.
         * @param {boolean} big - Optional. Determines if the button is large.
         * @returns {string} - The generated CSS class string.
         */
        buttonClass(isPrimary, big = false) {
            return `btn btn-m ${isPrimary ? "btn-primary" : ""} ${!big ? "btn-sm" : ""}`;
        },
        /**
         * Returns the CSS class based on the severity rating.
         * Maps severity levels to appropriate CSS classes.
         * @param {string} severityRating - The severity rating (e.g., "Low", "Medium").
         * @returns {string} - The corresponding CSS class.
         */
        getSeverityClass(severityRating) {
            const severityClasses = {
                "Low": "c-hand text-success",
                "Medium": "c-hand text-warning",
                "High": "c-hand text-error",
                "Critical": "c-hand text-error text-bold",
                "None": "c-hand text-gray"
            };
            return severityClasses[severityRating] || "c-hand text-gray"; // Default to gray if undefined
        },
        /**
         * Copies the current CVSS vector string to the clipboard and updates the URL hash.
         */
        copyVector() {
            navigator.clipboard.writeText(this.vector); // Copy vector to clipboard
            window.location.hash = this.vector; // Update URL hash with the vector
        },
        /**
         * Handles metric updates triggered by button clicks.
         * Updates the Vector instance and refreshes the CVSS instance and URL.
         * @param {string} metric - The metric being updated.
         * @param {string} value - The new value for the metric.
         */
        onButton(metric, value) {
            this.vectorInstance.updateMetric(metric, value); // Update metric in the vector instance
            window.location.hash = this.vector; // Update URL hash
            this.updateCVSSInstance();
        },
        /**
         * Updates the button states based on the provided vector string.
         * Also refreshes the CVSS instance to reflect the new vector state.
         * @param {string} vector - The CVSS vector string to set.
         */
        setButtonsToVector(vector) {
            try {
                this.vectorInstance.updateMetricsFromVectorString(vector);
                this.updateCVSSInstance();
            } catch (error) {
                console.error("Error updating vector:", error.message);
            }
        },
        /**
         * Initializes or updates the CVSS instance based on the current vector.
         * Also updates the macro vector representation.
         */
        updateCVSSInstance() {
            this.cvssInstance = new CVSS40(this.vectorInstance); // Create a new CVSS instance
            this.macroVector = this.vectorInstance.equivalentClasses; // Update macro vector
        },
        /**
         * Resets the vector instance to its default state and clears the URL hash.
         */
        onReset() {
            window.location.hash = ""; // Clear URL hash
            this.resetSelected(); // Reset vector to default state
            this.updateCVSSInstance(); // Refresh CVSS instance
        },
        /**
         * Resets the vector instance to a new default Vector object.
         */
        resetSelected() {
            this.vectorInstance = new Vector();
        },
        /**
         * Splits an object into chunks of a specified size.
         * Useful for dividing data into manageable parts for display.
         * @param {object} object - The object to split.
         * @param {number} chunkSize - The size of each chunk.
         * @returns {array} - An array of chunks, each containing part of the original object.
         */
        splitObjectEntries(object, chunkSize) {
            return Object.entries(object).reduce((result, entry, index) => {
                if (index % chunkSize === 0) result.push([]); // Start a new chunk
                result[result.length - 1].push(entry); // Add entry to the current chunk
                return result;
            }, []);
        }
    },
    computed: {
        /**
         * Computes the current vector string from the Vector instance.
         * @returns {string} - The raw CVSS vector string.
         */
        vector() {
            return this.vectorInstance.raw;
        },
        /**
         * Computes the current CVSS score based on the CVSS instance.
         * @returns {number} - The calculated CVSS score.
         */
        score() {
            return this.cvssInstance ? this.cvssInstance.score : 0;
        },
        /**
         * Computes the current severity rating based on the CVSS instance.
         * @returns {string} - The severity rating (e.g., "Low", "High").
         */
        severityRating() {
            return this.cvssInstance ? this.cvssInstance.severity : "None";
        }
    },
    async beforeMount() {
        await this.loadConfigData();
        this.setButtonsToVector(window.location.hash.slice(1));
    },
    mounted() {
        // Listen for URL hash changes and update the vector accordingly
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash.slice(1));
        });

        // Setup a resize observer to track changes in the header's height
        const headerElement = document.getElementById('header');
        if (headerElement) {
            const resizeObserver = new ResizeObserver(() => {
                this.header_height = headerElement.clientHeight;
            });
            resizeObserver.observe(headerElement);
        } else {
            console.error("Header element not found");
        }
    }
});

app.mount("#app");

