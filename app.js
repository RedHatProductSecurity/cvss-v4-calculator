const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: cvssConfig,
            cvssLookupData: cvssLookup,
            cvssMacroVectorDetailsData: cvssMacroVectorDetails,
            cvssMacroVectorValuesData: cvssMacroVectorValues,
            showDetails: false,
            columns: [Object.keys(cvssConfig).slice(0, 2),
                      Object.keys(cvssConfig).slice(2, 4)],
        }
    },
    methods: {
        buttonClass(isPrimary) {
            if(isPrimary) {
                return "btn btn-sm btn-primary"
            }
            else {
                return "btn btn-sm"
            }
        },
        baseScoreClass(qualScore) {
            if(qualScore == "Low") {
                return "c-hand text-success"
            }
            else if(qualScore == "Medium") {
                return "c-hand text-warning"
            }
            else if(qualScore == "High") {
                return "c-hand text-error"
            }
            else if(qualScore == "Critical") {
                return "c-hand text-error text-bold"
            }
            else {
                return "c-hand text-gray"
            }
        },
        copyVector() {
            navigator.clipboard.writeText(this.vector)
            window.location.hash = this.vector
        },
        onButton(metricData, value) {
            metricData.selected = value
            window.location.hash = this.vector
        },
        setButtonsToVector(vector) {
            metrics = vector.split("/")
            metricMap = {}
            for(index in metrics) {
                values = metrics[index].split(":")
                metricMap[values[0]] = values[1]
            }

            for(score in this.cvssConfigData) {
                scoreData = this.cvssConfigData[score]
                for(metric in scoreData) {
                    metricData = scoreData[metric]
                    if(metricMap[metricData.short]) {
                        metricData.selected = metricMap[metricData.short]
                    }
                    else {
                        metricData.selected = Object.values(metricData.options)[0].value
                    }
                }
            }
        },
        checkMetric(metric, value) {
            selected = this.selectedValues[metric]

            // E:X is the same as E:A
            if(metric == "E" && selected == "X") {
                return value == "A"
            }

            // The three security requirements metrics have X equivalent to M.
            // CR:X is the same as CR:M
            if(metric == "CR" && selected == "X") {
                return value == "M"
            }
            // IR:X is the same as IR:M
            if(metric == "IR" && selected == "X") {
                return value == "M"
            }
            // AR:X is the same as AR:M
            if(metric == "AR" && selected == "X") {
                return value == "M"
            }

            // All other environmental metrics just overwrite base score values,
            // so if they’re not defined just use the base score value.
            if(Object.keys(this.selectedValues).includes("M" + metric)) {
                modified_selected = this.selectedValues["M" + metric]
                if(modified_selected != "X" && modified_selected != "S") {
                    return value == modified_selected
                }
            }

            return value == selected
        },
        onReset() {
            window.location.hash = ""
        }
    },
    computed: {
        vector() {
            value = "CVSS:4.0"
            for(score in this.cvssConfigData) {
                scoreData = this.cvssConfigData[score]
                for(metric in scoreData) {
                    metricData = scoreData[metric]
                    if(metricData.selected != "X") {
                        value = value.concat("/" + metricData.short + ":" + metricData.selected)
                    }
                }
            }
            return value
        },
        selectedValues() {
            result = {}
            for(score in this.cvssConfigData) {
                scoreData = this.cvssConfigData[score]
                for(metric in scoreData) {
                    metricData = scoreData[metric]
                        result[metricData.short] = metricData.selected
                }
            }
            return result
        },
        macroVector() {
            // EQ1: 0-AV:N and PR:N and UI:N
            //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
            //      2-AV:P or not(AV:N or PR:N or UI:N)

            if(this.checkMetric("AV", "N")
               && this.checkMetric("PR", "N")
               && this.checkMetric("UI", "N")) {
                eq1 = "0"
            }
            else if((this.checkMetric("AV", "N")
                     || this.checkMetric("PR", "N")
                     || this.checkMetric("UI", "N"))
                    && !(this.checkMetric("AV", "N")
                         && this.checkMetric("PR", "N")
                         && this.checkMetric("UI", "N"))
                    && !this.checkMetric("AV", "P")) {
                eq1 = "1"
            }
            else if(this.checkMetric("AV", "P")
                    || !(this.checkMetric("AV", "N")
                         || this.checkMetric("PR", "N")
                         || this.checkMetric("UI", "N"))) {
                eq1 = "2"
            }
            else {
                console.log("Error computing EQ1")
                eq1 = 9
            }

            // EQ2: 0-(AC:L and AT:N)
            //      1-(not(AC:L and AT:N))

            if(this.checkMetric("AC", "L") && this.checkMetric("AT", "N")) {
                eq2 = "0"
            }
            else if(!(this.checkMetric("AC", "L") && this.checkMetric("AT", "N"))) {
                eq2 = "1"
            }
            else {
                console.log("Error computing EQ2")
                eq2 = 9
            }

            // EQ3 Revised: 0-(VC:H and VI:H)
            //              1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
            //              2-not (VC:H or VI:H or VA:H)
            //              3-(VC:N and VI:N and VA:N and SC:N and SI:N and SA:N)  PRIORITY

            if(this.checkMetric("VC", "N")
               && this.checkMetric("VI", "N")
               && this.checkMetric("VA", "N")
               && this.checkMetric("SC", "N")
               && this.checkMetric("SI", "N")
               && this.checkMetric("SA", "N")) {
                eq3 = 3
            }
            else if(this.checkMetric("VC", "H") && this.checkMetric("VI", "H")) {
                eq3 = 0
            }
            else if(!(this.checkMetric("VC", "H")
                      && this.checkMetric("VI", "H"))
                    && (this.checkMetric("VC", "H")
                        || this.checkMetric("VI", "H")
                        || this.checkMetric("VA", "H"))) {
                eq3 = 1
            }
            else if(!(this.checkMetric("VC", "H")
                      || this.checkMetric("VI", "H")
                      || this.checkMetric("VA", "H"))) {
                eq3 = 2
            }
            else {
                console.log("Error computing EQ3")
                eq3 = 9
            }

            // EQ4: 0-(MSI:S or MSA:S)
            //      1-(SC:H or SI:H or SA:H and not(MSI:S or MSA:S))
            //      2-((SC:L or N) and (SI:L or N) and (SA:L or N))
            //      3-(VC:N and VI:N and VA:N and SC:N and SI:N and SA:N)  PRIORITY

            if(this.checkMetric("VC", "N")
               && this.checkMetric("VI", "N")
               && this.checkMetric("VA", "N")
               && this.checkMetric("SC", "N")
               && this.checkMetric("SI", "N")
               && this.checkMetric("SA", "N")) {
                eq4 = 3
            }
            else if(this.checkMetric("MSI", "S") || this.checkMetric("MSA", "S")) {
                eq4 = 0
            }
            else if(this.checkMetric("SC", "H")
                    || this.checkMetric("SI", "H")
                    || this.checkMetric("SA", "H")
                    && !(this.checkMetric("MSI", "S")
                         || this.checkMetric("MSA", "S"))) {
                eq4 = 1
            }
            else if(((this.checkMetric("SC", "L") || this.checkMetric("SC", "N"))
                     && (this.checkMetric("SI", "L") || this.checkMetric("SI", "N"))
                     && (this.checkMetric("SA", "L") || this.checkMetric("SA", "N")))) {
                eq4 = 2
            }
            else {
                console.log("Error computing EQ4")
                eq4 = 9
            }

            // EQ5: 0-E:A
            //      1-E:P
            //      2-E:U

            if(this.checkMetric("E", "A")) {
                eq5 = 0
            }
            else if(this.checkMetric("E", "P")) {
                eq5 = 1
            }
            else if(this.checkMetric("E", "U")) {
                eq5 = 2
            }
            else {
                console.log("Error computing EQ5")
                eq5 = 9
            }

            // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
            //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

            if((this.checkMetric("CR", "H") && this.checkMetric("VC", "H"))
               || (this.checkMetric("IR", "H") && this.checkMetric("VI", "H"))
               || (this.checkMetric("AR", "H") && this.checkMetric("VA", "H"))) {
               eq6 = 0
            }
            else if(!((this.checkMetric("CR", "H") && this.checkMetric("VC", "H"))
                      || (this.checkMetric("IR", "H") && this.checkMetric("VI", "H"))
                      || (this.checkMetric("AR", "H") && this.checkMetric("VA", "H")))) {
               eq6 = 1
            }
            else {
                console.log("Error computing EQ6")
                eq6 = 9
            }

            return eq1 + eq2 + eq3 + eq4 + eq5 +eq6
        },
        baseScore() {
            lookup = this.macroVector
            // Exception for no impact on system
            if(lookup.includes("33")) {
                return "0.0"
            }
            value = this.cvssLookupData[lookup].base_score

            // Some magic :-D
            value = parseFloat(value)

            AV_diff={"N": 0.3, "A": 0.2, "L": 0.1, "P": 0}
            PR_diff={"N": 0.2, "L": 0.1, "H": 0}
            UI_diff={"N": 0.2, "P": 0.1, "A": 0}

            if(lookup[0] == "0") {
                value = value
            }
            if(lookup[0] == "1") {
                value_0 = parseFloat(this.cvssLookupData["0" + lookup.slice(1)].base_score)
                value = Math.min(value_0, value + AV_diff[this.selectedValues["AV"]] + PR_diff[this.selectedValues["PR"]] + UI_diff[this.selectedValues["UI"]] - 0.2)
            }
            if(lookup[0] == "2") {
                value_1 = parseFloat(this.cvssLookupData["1" + lookup.slice(1)].base_score)
                value = Math.min(value_1, value + AV_diff[this.selectedValues["AV"]] + PR_diff[this.selectedValues["PR"]] + UI_diff[this.selectedValues["UI"]])
            }
            // End of magic...

            return String(value)
        },
        qualScore() {
            lookup = this.macroVector
            // Exception for no impact on system
            if(lookup.includes("33")) {
                return "None"
            }
            value = this.cvssLookupData[lookup].qual_score
            return value
        },
    },
    mounted() {
        this.setButtonsToVector(window.location.hash)
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash)
        })
    }
})

app.mount("#app")