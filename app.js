// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: cvssConfig,
            maxComposedData: maxComposed,
            maxHammingData: maxHamming,
            cvssMacroVectorDetailsData: cvssMacroVectorDetails,
            cvssMacroVectorValuesData: cvssMacroVectorValues,
            showDetails: false,
            cvssSelected: null,
            header_height: 0,
            enviro_default: "H",
            currentLookup: cvssLookup_global,
        }
    },
    methods: {
        getvalueEqLookup(lookup,i){ 
            eq=parseInt(lookup[i])
            eq_val = maxComposed["eq"+String(i+1)][eq]
            return eq_val
        },
        extractValueMetric(metric,str){
            //indexOf gives first index of the metric, we then need to go over its size
            extracted = str.slice(str.indexOf(metric) + metric.length + 1)
            //remove what follow
            if(extracted.indexOf('/')>0) {
                metric_val = extracted.substring(0, extracted.indexOf('/'));
            }
            else{
                //case where it is the last metric so no ending /
                metric_val = extracted
            }
            return metric_val
        },
        buttonClass(isPrimary, big=false) {
            result = "btn btn-m"
            if(isPrimary) {
                result += " btn-primary"
            }
            if(!big) {
                result += " btn-sm"
            }

            return result
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
        onButton(metric, value) {
            this.cvssSelected[metric] = value
            window.location.hash = this.vector
        },
        setButtonsToVector(vector) {
            this.resetSelected()
            metrics = vector.split("/")
            for(index in metrics) {
                [key, value] = metrics[index].split(":")
                if(key in this.cvssSelected) {
                    this.cvssSelected[key] = value
                }
            }
        },
        m(metric) {
            selected = this.cvssSelected[metric]

            // E:X is the same as E:A
            if(metric == "E" && selected == "X") {
                return "A"
            }
            // The three security requirements metrics have X equivalent to H.
            // CR:X is the same as CR:H
            if(metric == "CR" && selected == "X") {
                return this.enviro_default;
            }
            // IR:X is the same as IR:H
            if(metric == "IR" && selected == "X") {
                return this.enviro_default;
            }
            // AR:X is the same as AR:H
            if(metric == "AR" && selected == "X") {
                return this.enviro_default;
            }

            if (metric=='MSI' && selected=='X' && this.cvssSelected['SI']=="S"){
                return "S"
            }

            if (metric=='MSA' && selected=='X' && this.cvssSelected['SA']=="S"){
                return "S"
            }

            // All other environmental metrics just overwrite base score values,
            // so if they’re not defined just use the base score value.
            if(Object.keys(this.cvssSelected).includes("M" + metric)) {
                modified_selected = this.cvssSelected["M" + metric]
                if(modified_selected != "X" && modified_selected != "S") {
                    return modified_selected
                }
            }

            return selected
        },
        onReset() {
            window.location.hash = ""
        },
        resetSelected() {
            this.cvssSelected = {}
            for([metricType, metricTypeData] of Object.entries(this.cvssConfigData)) {
                for([metricGroup, metricGroupData] of Object.entries(metricTypeData.metric_groups)) {
                    for([metric, metricData] of Object.entries(metricGroupData)) {
                        this.cvssSelected[metricData.short] = metricData.selected
                    }
                }
            }
        },
        splitObjectEntries(object, chunkSize) {
            arr = Object.entries(object)
            res = [];
            for(let i = 0; i < arr.length; i += chunkSize) {
                chunk = arr.slice(i, i + chunkSize)
                res.push(chunk)
            }
            return res
        }
    },
    computed: {
        vector() {
            value = "CVSS:4.0"
            for(metric in this.cvssSelected) {
                selected = this.cvssSelected[metric]
                if(selected != "X") {
                    value = value.concat("/" + metric + ":" + selected)
                }
            }
            return value
        },
        macroVector() {
            // EQ1: 0-AV:N and PR:N and UI:N
            //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
            //      2-AV:P or not(AV:N or PR:N or UI:N)

            if(this.m("AV") == "N" && this.m("PR") == "N" && this.m("UI") == "N") {
                eq1 = "0"
            }
            else if((this.m("AV") == "N" || this.m("PR") == "N" || this.m("UI") == "N")
                    && !(this.m("AV") == "N" && this.m("PR") == "N" && this.m("UI") == "N")
                    && !(this.m("AV") == "P")) {
                eq1 = "1"
            }
            else if(this.m("AV") == "P"
                    || !(this.m("AV") == "N" || this.m("PR") == "N" || this.m("UI") == "N")) {
                eq1 = "2"
            }
            else {
                console.log("Error computing EQ1")
                eq1 = 9
            }

            // EQ2: 0-(AC:L and AT:N)
            //      1-(not(AC:L and AT:N))

            if(this.m("AC") == "L" && this.m("AT") == "N") {
                eq2 = "0"
            }
            else if(!(this.m("AC") == "L" && this.m("AT") == "N")) {
                eq2 = "1"
            }
            else {
                console.log("Error computing EQ2")
                eq2 = 9
            }

            // EQ3: 0-(VC:H and VI:H)
            //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
            //      2-not (VC:H or VI:H or VA:H)
            //      3-(VC:N and VI:N and VA:N and SC:N and SI:N and SA:N)  PRIORITY

            if(this.m("VC") == "N" && this.m("VI") == "N" && this.m("VA") == "N"
               && this.m("SC") == "N" && this.m("SI") == "N" && this.m("SA") == "N") {
                eq3 = 3
            }
            else if(this.m("VC") == "H" && this.m("VI") == "H") {
                eq3 = 0
            }
            else if(!(this.m("VC") == "H" && this.m("VI") == "H")
                    && (this.m("VC") == "H" || this.m("VI") == "H" || this.m("VA") == "H")) {
                eq3 = 1
            }
            else if(!(this.m("VC") == "H" || this.m("VI") == "H" || this.m("VA") == "H")) {
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

            if(this.m("VC") == "N" && this.m("VI") == "N" && this.m("VA") == "N"
               && this.m("SC") == "N" && this.m("SI") == "N" && this.m("SA") == "N") {
                eq4 = 3
            }
            else if(this.m("MSI") == "S" || this.m("MSA") == "S") {
                eq4 = 0
            }
            else if(this.m("SC") == "H" || this.m("SI") == "H"
                    || this.m("SA") == "H" && !(this.m("MSI") == "S" || this.m("MSA") == "S")) {
                eq4 = 1
            }
            else if(((this.m("SC") == "L" || this.m("SC") == "N")
                     && (this.m("SI") == "L" || this.m("SI") == "N")
                     && (this.m("SA") == "L" || this.m("SA") == "N"))) {
                eq4 = 2
            }
            else {
                console.log("Error computing EQ4")
                eq4 = 9
            }

            // EQ5: 0-E:A
            //      1-E:P
            //      2-E:U

            if(this.m("E") == "A") {
                eq5 = 0
            }
            else if(this.m("E") == "P") {
                eq5 = 1
            }
            else if(this.m("E") == "U") {
                eq5 = 2
            }
            else {
                console.log("Error computing EQ5")
                eq5 = 9
            }

            // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
            //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

            if((this.m("CR") == "H" && this.m("VC") == "H")
               || (this.m("IR") == "H" && this.m("VI") == "H")
               || (this.m("AR") == "H" && this.m("VA") == "H")) {
               eq6 = 0
            }
            else if(!((this.m("CR") == "H" && this.m("VC") == "H")
                      || (this.m("IR") == "H" && this.m("VI") == "H")
                      || (this.m("AR") == "H" && this.m("VA") == "H"))) {
               eq6 = 1
            }
            else {
                console.log("Error computing EQ6")
                eq6 = 9
            }

            return eq1 + eq2 + eq3 + eq4 + eq5 +eq6
        },
        baseScore() {
            //define lookup table
            lookuptable = this.currentLookup;

            AV_levels={"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
            PR_levels={"N": 0.0, "L": 0.1, "H": 0.2}
            UI_levels={"N": 0.0, "P": 0.1, "A": 0.2}

            AC_levels={'L':0.0, 'H':0.1}
            AT_levels={'N':0.0, 'P':0.1}
        
            VC_levels={'H':0.0, 'L':0.1, 'N':0.2}
            VI_levels={'H':0.0, 'L':0.1, 'N':0.2}
            VA_levels={'H':0.0, 'L':0.1, 'N':0.2}    

            SC_levels={'H':0.1, 'L':0.2, 'N':0.3}
            SI_levels={'S':0.0, 'H':0.1, 'L':0.2, 'N':0.3}
            SA_levels={'S':0.0, 'H':0.1, 'L':0.2, 'N':0.3}

            CR_levels={'H':0.0, 'M':0.1, 'L':0.2}
            IR_levels={'H':0.0, 'M':0.1, 'L':0.2}
            AR_levels={'H':0.0, 'M':0.1, 'L':0.2}

            E_levels={'U': 0.2, 'P': 0.1, 'A': 0}


            lookup = this.macroVector
            // Exception for no impact on system
            if(lookup.includes("33")) {
                return "0.0"
            }
            value = lookuptable[lookup]

            eq1_val = parseInt(lookup[0])
            eq2_val = parseInt(lookup[1])
            eq3_val = parseInt(lookup[2])
            eq4_val = parseInt(lookup[3])
            eq5_val = parseInt(lookup[4])
            eq6_val = parseInt(lookup[5])

            //compute next lower macro, it can also not exist
            eq1_next_lower_macro = "".concat(eq1_val+1,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val)
            eq2_next_lower_macro = "".concat(eq1_val,eq2_val+1,eq3_val,eq4_val,eq5_val,eq6_val)
            
            //eq3 and eq6 are related
            if (eq3==1 && eq6==1){
                //11 --> 21
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val)
            }
            else if (eq3==0 && eq6==1){
                //01 --> 11
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val) 
            }
            else if (eq3==1 && eq6==0){
                //10 --> 11
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1) 
            }
            else if (eq3==0 && eq6==0){
                //00 --> 01
                //00 --> 10
                eq3eq6_next_lower_macro_left = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1)
                eq3eq6_next_lower_macro_right = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val)
            }
            else{
                //21 --> 32 (do not exist)
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val+1)
            }


            eq4_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val+1,eq5_val,eq6_val)
            eq5_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val+1,eq6_val)


            //get their score, if the next lower macro score do not exist the result is NaN
            score_eq1_next_lower_macro = lookuptable[eq1_next_lower_macro]
            score_eq2_next_lower_macro = lookuptable[eq2_next_lower_macro]

            if (eq3==0 && eq6==0){
                //multiple path take the one with higher score
                score_eq3eq6_next_lower_macro_left = lookuptable[eq3eq6_next_lower_macro_left]
                score_eq3eq6_next_lower_macro_right = lookuptable[eq3eq6_next_lower_macro_right]

                if (score_eq3eq6_next_lower_macro_left>score_eq3eq6_next_lower_macro_right){
                    score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
                }
                else{
                    score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
                }
            }
            else{
                score_eq3eq6_next_lower_macro = lookuptable[eq3eq6_next_lower_macro]
            }


            score_eq4_next_lower_macro = lookuptable[eq4_next_lower_macro]
            score_eq5_next_lower_macro = lookuptable[eq5_next_lower_macro]

            //get all max vector for the eq
            eq1_maxes = this.getvalueEqLookup(lookup,0)
            eq2_maxes = this.getvalueEqLookup(lookup,1)
            eq3_eq6_maxes = this.getvalueEqLookup(lookup,2)[lookup[5]]
            eq4_maxes = this.getvalueEqLookup(lookup,3)
            eq5_maxes = this.getvalueEqLookup(lookup,4)

            //compose them
            max_vectors = []
            for (eq1_max of eq1_maxes){
                for (eq2_max of eq2_maxes){
                    for (eq3_eq6_max of eq3_eq6_maxes){
                        for (eq4_max of eq4_maxes){
                            for (eq5max of eq5_maxes){
                                    max_vectors.push(eq1_max+eq2_max+eq3_eq6_max+eq4_max+eq5max)
                            }
                        }
                    }
                }
            }

            if (max_vectors==undefined){
                return "0.0"
            }


            // compute hamming distance
            for (let i = 0; i < max_vectors.length; i++) {
                tmp_vector = max_vectors[i]
                //cannot have a negative distance if less than max
                hamming_distance_AV = AV_levels[this.m("AV")]-AV_levels[this.extractValueMetric("AV",tmp_vector)]
                hamming_distance_PR = PR_levels[this.m("PR")]-PR_levels[this.extractValueMetric("PR",tmp_vector)]
                hamming_distance_UI = UI_levels[this.m("UI")]-UI_levels[this.extractValueMetric("UI",tmp_vector)]

                hamming_distance_AC = AC_levels[this.m("AC")]-AC_levels[this.extractValueMetric("AC",tmp_vector)]
                hamming_distance_AT = AT_levels[this.m("AT")]-AT_levels[this.extractValueMetric("AT",tmp_vector)]

                hamming_distance_VC = VC_levels[this.m("VC")]-VC_levels[this.extractValueMetric("VC",tmp_vector)]
                hamming_distance_VI = VI_levels[this.m("VI")]-VI_levels[this.extractValueMetric("VI",tmp_vector)]
                hamming_distance_VA = VA_levels[this.m("VA")]-VA_levels[this.extractValueMetric("VA",tmp_vector)]   


                if(this.m("MSI") == "S" && this.m("MSA")=="S"){
                    //use MSI and MSA
                    hamming_distance_SI = SI_levels[this.m("MSI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]             
                    hamming_distance_SA = SA_levels[this.m("MSA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]  
                }
                else if (this.m("MSI") == "S"){
                    //only MSI set to S
                    hamming_distance_SI = SI_levels[this.m("MSI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]
                    hamming_distance_SA = SA_levels[this.m("SA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]
                }
                else if(this.m("MSA") == "S"){
                    //only MSA set to S
                    hamming_distance_SI = SI_levels[this.m("SI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]
                    hamming_distance_SA = SA_levels[this.m("MSA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)] 
                }
                else {
                    //none set to S
                    hamming_distance_SI = SI_levels[this.m("SI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]     
                    hamming_distance_SA = SA_levels[this.m("SA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]  
                }
                hamming_distance_SC = SC_levels[this.m("SC")]-SC_levels[this.extractValueMetric("SC",tmp_vector)]

                hamming_distance_CR = CR_levels[this.m("CR")]-CR_levels[this.extractValueMetric("CR",tmp_vector)]
                hamming_distance_IR = IR_levels[this.m("IR")]-IR_levels[this.extractValueMetric("IR",tmp_vector)]
                hamming_distance_AR = AR_levels[this.m("AR")]-AR_levels[this.extractValueMetric("AR",tmp_vector)]


                //if any is less than zero this is not the right max
                if (hamming_distance_AV<0 || hamming_distance_PR<0 || hamming_distance_UI<0 || hamming_distance_AC<0 || hamming_distance_AT<0 || hamming_distance_VC<0 || hamming_distance_VI<0 || hamming_distance_VA<0 || hamming_distance_SC<0 || hamming_distance_SI<0 || hamming_distance_SA<0 || hamming_distance_CR<0 || hamming_distance_IR<0 || hamming_distance_AR<0) {
                    continue
                }
                else{
                    //if multiple maxes exist to reach it it is enough the first one
                    break
                }
            }

            

            current_hamming_distance_eq1 = hamming_distance_AV + hamming_distance_PR + hamming_distance_UI
            current_hamming_distance_eq2 = hamming_distance_AC + hamming_distance_AT
            current_hamming_distance_eq3eq6 = hamming_distance_VC + hamming_distance_VI + hamming_distance_VA + hamming_distance_CR + hamming_distance_IR + hamming_distance_AR
            current_hamming_distance_eq4 = hamming_distance_SC + hamming_distance_SI + hamming_distance_SA
            current_hamming_distance_eq5 = 0


            step = 0.1

            //if the next lower macro score do not exist the result is Nan
            available_distance_eq1 = value - score_eq1_next_lower_macro
            available_distance_eq2 = value - score_eq2_next_lower_macro
            available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
            available_distance_eq4 = value - score_eq4_next_lower_macro
            available_distance_eq5 = value - score_eq5_next_lower_macro

            percent_to_next_eq1_hamming = 0
            percent_to_next_eq2_hamming = 0
            percent_to_next_eq3eq6_hamming = 0
            percent_to_next_eq4_hamming = 0
            percent_to_next_eq5_hamming = 0
            

            //some of them do not exist, we will find them by retrieving the score. If score null then do not exist
            n_existing_lower = 0

            normalized_hamming_eq1 = 0
            normalized_hamming_eq2 = 0
            normalized_hamming_eq3eq6 = 0
            normalized_hamming_eq4 = 0
            normalized_hamming_eq5 = 0

            //multiply by step because distance is pure
            maxHamming_eq1 = this.maxHammingData['eq1'][String(eq1_val)]*step
            maxHamming_eq2 = this.maxHammingData['eq2'][String(eq2_val)]*step
            maxHamming_eq3eq6 = this.maxHammingData['eq3'][String(eq3_val)][String(eq6_val)]*step
            maxHamming_eq4 = this.maxHammingData['eq4'][String(eq4_val)]*step


            if (!isNaN(available_distance_eq1)){
                n_existing_lower=n_existing_lower+1
                percent_to_next_eq1_hamming = (current_hamming_distance_eq1)/maxHamming_eq1
                //can be nan if divided by zero
                if(isNaN(percent_to_next_eq1_hamming)){
                    percent_to_next_eq1_hamming=0
                }
                
                normalized_hamming_eq1 = available_distance_eq1*percent_to_next_eq1_hamming
                
            }

            if (!isNaN(available_distance_eq2)){
                n_existing_lower=n_existing_lower+1
                percent_to_next_eq2_hamming = (current_hamming_distance_eq2)/maxHamming_eq2
                if(isNaN(percent_to_next_eq2_hamming)){
                    percent_to_next_eq2_hamming=0
                }
                
                normalized_hamming_eq2 = available_distance_eq2*percent_to_next_eq2_hamming
            }

            if (!isNaN(available_distance_eq3eq6)){
                n_existing_lower=n_existing_lower+1
                percent_to_next_eq3eq6_hamming = (current_hamming_distance_eq3eq6)/maxHamming_eq3eq6
                if(isNaN(percent_to_next_eq3eq6_hamming)){
                    percent_to_next_eq3eq6_hamming=0
                }
                
                normalized_hamming_eq3eq6 = available_distance_eq3eq6*percent_to_next_eq3eq6_hamming
            }

            if (!isNaN(available_distance_eq4)){
                n_existing_lower=n_existing_lower+1
                percent_to_next_eq4_hamming = (current_hamming_distance_eq4)/maxHamming_eq4
                if(isNaN(percent_to_next_eq4_hamming)){
                    percent_to_next_eq4_hamming=0
                }
                
                normalized_hamming_eq4 = available_distance_eq4*percent_to_next_eq4_hamming
            }

            if (!isNaN(available_distance_eq5)){
                //for eq5 is always 0 the percentage
                n_existing_lower=n_existing_lower+1
                percent_to_next_eq5_hamming = 0
                if(isNaN(percent_to_next_eq5_hamming)){
                    percent_to_next_eq5_hamming=0
                }
                
                normalized_hamming_eq5 = available_distance_eq5*percent_to_next_eq5_hamming
            }

            if (n_existing_lower==0) {
                mean_distance = 0
            } else { //sometimes we need to go up but there is nothing there, or down but there is nothing there so it's a change of 0.
                mean_distance = (normalized_hamming_eq1+normalized_hamming_eq2+normalized_hamming_eq3eq6+normalized_hamming_eq4+normalized_hamming_eq5)/n_existing_lower
            }
            value = parseFloat(value) - parseFloat(mean_distance);

            
                        
            if(value<0){
                value = 0.0
            }

            if(value>10){
                value = 10.0
            }

            return value.toFixed(1)
        },
        qualScore() {
            if(this.baseScore == 0) {
                return "None"
            }
            else if(this.baseScore < 4.0) {
                return "Low"
            }
            else if(this.baseScore < 7.0) {
                return "Medium"
            }
            else if(this.baseScore < 9.0) {
                return "High"
            }
            else {
                return "Critical"
            }
        },
    },
    beforeMount() {
        this.resetSelected()
    },
    mounted() {
        this.setButtonsToVector(window.location.hash)
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash)
        })

        const resizeObserver = new ResizeObserver(() => {
            //console.log("Size changed")
            this.header_height = document.getElementById('header').clientHeight
        })

        resizeObserver.observe(document.getElementById('header'))
    }
})

app.mount("#app")
