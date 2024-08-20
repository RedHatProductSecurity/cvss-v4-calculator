// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null, // Initialize as null, will be populated after loading JSON
            expectedMetricOrder: CVSS40.EXPECTED_METRIC_ORDER, // Expected order of metrics as per CVSS 4.0
            showDetails: false, // Controls the display of detailed metric information
            vectorMetrics: {},  // Initialize as an empty object to hold selected metric values
            header_height: 0, // To store the height of the header, useful for responsive design
            macroVector: null, // Placeholder for a summarized vector representation
            cvssInstance: null // Placeholder for the CVSS40 class instance
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
            if (!this.vectorMetrics) {
                this.vectorMetrics = {};
            }
            this.vectorMetrics[metric] = value;
            window.location.hash = this.vector;
            this.updateCVSSInstance();
        },
        setButtonsToVector(vector) {
            if (!this.vectorMetrics) {
                this.vectorMetrics = {};
            }
            this.resetSelected();
            const metrics = vector.split("/");
            const prefix = metrics[0].slice(1);
            if (prefix !== "CVSS:4.0") {
                console.log("Error invalid vector, missing CVSS v4.0 prefix");
                return;
            }
            metrics.shift();

            const toSelect = {};
            let oi = 0;
            for (const index in metrics) {
                const [key, value] = metrics[index].split(":");
                let expected = Object.entries(this.expectedMetricOrder)[oi++];
                while (true) {
                    // If out of possible metrics ordering, it not a valid value thus
                    // the vector is invalid
                    if (expected === undefined) {
                        console.log("Error invalid vector, too many metric values");
                        return;
                    }
                    if (key !== expected[0]) {
                        // If not this metric but is mandatory, the vector is invalid
                        // As the only mandatory ones are from the Base group, 11 is the
                        // number of metrics part of it.
                        if (oi <= 11) {
                            console.log("Error invalid vector, missing mandatory metrics");
                            return;
                        }
                        // If a non-mandatory, retry
                        expected = Object.entries(this.expectedMetricOrder)[oi++];
                        continue;
                    }
                    break;
                }
                // The value MUST be part of the metric's values, case insensitive
                if (!expected[1].includes(value)) {
                    console.log(`Error invalid vector, for key ${key}, value ${value} is not in ${expected[1]}`);
                    return;
                }
                if (key in this.vectorMetrics) {
                    toSelect[key] = value;
                }
            }
            
            // Apply if it is compliant
            for (const key in toSelect) {
                this.vectorMetrics[key] = toSelect[key];
            }
            // Recalculate the CVSS instance with the updated data
            this.updateCVSSInstance();
        },
        updateCVSSInstance() {
            // Create a new instance of CVSS40
            this.cvssInstance = new CVSS40(this.vector);
            // Update the macro vector result
            this.macroVector = this.cvssInstance.macroVectorResult;
        },
        onReset() {
            window.location.hash = "";
            this.resetSelected();
            this.updateCVSSInstance();
        },
        resetSelected() {
            this.vectorMetrics = {};
            if (this.cvssConfigData) {
                // Loop through the cvssConfigData to set the default selections
                for (const [metricType, metricTypeData] of Object.entries(this.cvssConfigData)) {
                    for (const [metricGroup, metricGroupData] of Object.entries(metricTypeData.metric_groups)) {
                        for (const [metric, metricData] of Object.entries(metricGroupData)) {
                            this.vectorMetrics[metricData.short] = metricData.selected;
                        }
                    }
                }
            }
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
            let value = "CVSS:4.0";
            for (const metric in this.expectedMetricOrder) {
                const selected = this.vectorMetrics[metric];
                if (selected !== "X") {
                    value = value.concat("/" + metric + ":" + selected);
                }
            }
            return value;
        },
        score() {
            return this.cvssInstance ? this.cvssInstance.baseScore : 0;
        },
        qualScore() {
            return this.cvssInstance ? this.cvssInstance.baseSeverity : "None";
        }
    },
    async beforeMount() {
        await this.loadConfigData(); // Load the config data before mounting
        this.setButtonsToVector(window.location.hash);
    },
    mounted() {
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash);
        });

        const resizeObserver = new ResizeObserver(() => {
            this.header_height = document.getElementById('header').clientHeight;
        });

        resizeObserver.observe(document.getElementById('header'));
    }
});

app.mount("#app");
