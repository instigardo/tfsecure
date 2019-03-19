/*
Copyright 2019 Himanshu Saxena

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform/terraform"
)

func main() {
	var tfPlanFile string
	flag.StringVar(&tfPlanFile, "tfplanfile", "", "Terraform generated plan file")
	var policyPath string
	flag.StringVar(&policyPath, "policypath", "", "Policy to be used for testing terraform plan")
	flag.Parse()
	if tfPlanFile == "" || policyPath == "" {
		defaultFlag := " Usage of tfsecure:\n" +
			"  -policypath string\n" +
			"  Policy to be used for testing terraform plan\n" +
			"  -tfplanfile string\n" +
			"  Terraform generated plan file"
		fmt.Fprintln(os.Stderr, defaultFlag)
		os.Exit(1)
	}

	parsedPlan, err := planParser(tfPlanFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("=========================================================================")
	fmt.Println("Verifying plan against secure policy")
	fmt.Println("=========================================================================")
	builtPolicy := policyBuilder(policyPath)
	policyChecker(builtPolicy, parsedPlan)
	fmt.Println("=========================================================================")
	fmt.Println("Tests Ran: " + strconv.Itoa(testsRan) + " | Tests Passed: " + strconv.Itoa(testsPassed) + " | Tests Failed: " + strconv.Itoa(testsFailed))
	fmt.Println("=========================================================================")

}

var testsPassed int
var testsRan int
var testsFailed int

func policyChecker(builtPolicy []interface{}, plan interface{}) string {

	for _, policy := range builtPolicy {
		fmt.Println(parse(policy)["resource_type"])
		findKey(policy, plan)
	}
	fmt.Println("=========================================================================")

	return ""
}

func parse(json interface{}) map[string]interface{} {
	return json.(map[string]interface{})
}

func parseArr(json interface{}) []interface{} {
	return json.([]interface{})
}

func findKey(policy interface{}, plan interface{}) {
	for pkey := range parse(plan) {
		if strings.Contains(pkey, parse(policy)["resource_type"].(string)) {
			for _, rule := range parseArr(parse(policy)["rules"]) {
				description := parse(rule)["description"].(string)
				found := false
				ruleResult := false

				for key, value := range parse(parse(plan)[pkey]) {
					if keyContains(key, parse(rule)["property"].(string)) {
						found = true
						if keyContains(value.(string), parse(rule)["value"].(string)) {
							if !parse(rule)["invert"].(bool) {
								ruleResult = true
							}

						} else {
							ruleResult = false
						}
					}
				}
				if found {
					testOutput(ruleResult, description)
				}

			}
		} else if reflect.TypeOf(plan.(map[string]interface{})[pkey]).Kind() == reflect.Map {
			findKey(policy, plan.(map[string]interface{})[pkey])
		}
	}
}

func testOutput(result bool, ruleDesc string) {
	fmt.Println("=========================================================================")
	testsRan++
	if result {
		fmt.Println("\u2713" + " | " + ruleDesc)
		testsPassed++
	} else {
		fmt.Println("\u2717" + " | " + ruleDesc)
		testsFailed++
	}
	fmt.Println("=========================================================================")

}

func keyContains(key string, rulekey string) (contains bool) {
	for _, k := range strings.Split(rulekey, ".") {
		if !strings.Contains(key, k) {
			return false
		}
	}
	return true
}

func getKeys(json interface{}) []int {
	mymap := make(map[int]string)
	keys := make([]int, 0, len(mymap))
	for k := range mymap {
		keys = append(keys, k)
	}
	return keys
}

func policyBuilder(policyPath string) []interface{} {
	var builtPolicy []interface{}
	files, err := ioutil.ReadDir(policyPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		policy, err := ioutil.ReadFile(policyPath + "/" + file.Name())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		var parsedPolicy interface{}
		err = json.Unmarshal(policy, &parsedPolicy)
		builtPolicy = append(builtPolicy, parsedPolicy)
	}
	return builtPolicy
}

type output map[string]interface{}

func planParser(planfile string) (interface{}, error) {
	f, err := os.Open(planfile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	plan, err := terraform.ReadPlan(f)
	if err != nil {
		return "", err
	}
	diff := output{}
	for _, v := range plan.Diff.Modules {
		convertModuleDiff(diff, v)
	}

	j, err := json.MarshalIndent(diff, "", "    ")
	if err != nil {
		return "", err
	}
	var parsedPlan interface{}
	err = json.Unmarshal(j, &parsedPlan)
	return parsedPlan, nil
}

func insert(out output, path []string, key string, value interface{}) {
	if len(path) > 0 && path[0] == "root" {
		path = path[1:]
	}
	for _, elem := range path {
		switch nested := out[elem].(type) {
		case output:
			out = nested
		default:
			new := output{}
			out[elem] = new
			out = new
		}
	}
	out[key] = value
}

func convertModuleDiff(out output, diff *terraform.ModuleDiff) {
	insert(out, diff.Path, "destroy", diff.Destroy)
	for k, v := range diff.Resources {
		convertInstanceDiff(out, append(diff.Path, k), v)
	}
}

func convertInstanceDiff(out output, path []string, diff *terraform.InstanceDiff) {
	insert(out, path, "destroy", diff.Destroy)
	insert(out, path, "destroy_tainted", diff.DestroyTainted)
	for k, v := range diff.Attributes {
		insert(out, path, k, v.New)
	}
}
