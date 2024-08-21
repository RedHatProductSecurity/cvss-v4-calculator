// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null, // Initialize as null, will be populated after loading JSON
            cvssMacroVectorDetailsData: CVSS40.MACRO_VECTOR_DETAILS,
            cvssMacroVectorValuesData: CVSS40.MACRO_VECTOR_VALUES,
            showDetails: false, // Controls the display of detailed metric information
            header_height: 0, // To store the height of the header, useful for responsive design
            macroVector: null, // Placeholder for a summarized vector representation
            vectorInstance: new Vector(),
            cvssInstance: null // Placeholder for the CVSS40 class instance,
        }
    },
    methods: {
        async loadConfigData() {
            // Fetch the metrics.json file
            const response = await fetch('./metrics.json');
            const data = await response.json();
            this.cvssConfigData = data;
            this.resetSelected();
            this.updateCVSSInstance();
        },
        buttonClass(isPrimary, big = false) {
            let result = "btn btn-m";
            if (isPrimary) {
                result += " btn-primary";
            }
            if (!big) {
                result += " btn-sm";
            }
            return result;
        },
        scoreClass(qualScore) {
            if (qualScore === "Low") {
                return "c-hand text-success";
            }
            else if (qualScore === "Medium") {
                return "c-hand text-warning";
            }
            else if (qualScore === "High") {
                return "c-hand text-error";
            }
            else if (qualScore === "Critical") {
                return "c-hand text-error text-bold";
            }
            else {
                return "c-hand text-gray";
            }
        },
        copyVector() {
            navigator.clipboard.writeText(this.vector);
            window.location.hash = this.vector;
        },
        onButton(metric, value) {
            console.log(`Updating ${metric} to ${value}`);

            this.vectorInstance.updateMetric(metric, value);

            window.location.hash = this.vector;
            this.updateCVSSInstance();
        },
        setButtonsToVector(vector) {
            try {
                this.vectorInstance.updateMetricsFromStringVector(vector);

                // Recalculate the CVSS instance with the updated data
                this.updateCVSSInstance();
            } catch (error) {
                console.log("Error: " + error.message);
            }
        },
        updateCVSSInstance() {
            // Create a new instance of CVSS40
            this.cvssInstance = new CVSS40(this.vectorInstance);
            // Update the macro vector result
            this.macroVector = this.vectorInstance.getEquivalentClasses();
        },
        onReset() {
            window.location.hash = "";
            this.resetSelected();
            this.updateCVSSInstance();
        },
        resetSelected() {
            // Reinitialize the vectorInstance with a new Vector object
            this.vectorInstance = new Vector();
        },
        splitObjectEntries(object, chunkSize) {
            const arr = Object.entries(object);
            const res = [];
            for (let i = 0; i < arr.length; i += chunkSize) {
                const chunk = arr.slice(i, i + chunkSize);
                res.push(chunk);
            }
            return res;
        }
    },
    computed: {
        vector() {
            return this.vectorInstance.raw;
        },
        score() {
            return this.cvssInstance ? this.cvssInstance.score : 0;
        },
        qualScore() {
            return this.cvssInstance ? this.cvssInstance.severity : "None";
        }
    },
    async beforeMount() {
        await this.loadConfigData(); // Load the config data before mounting
        // Pass the vector without the #
        this.setButtonsToVector(window.location.hash.slice(1));
    },
    mounted() {
        window.addEventListener("hashchange", () => {
            // Pass the vector without the #
            this.setButtonsToVector(window.location.hash.slice(1));
        });

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
