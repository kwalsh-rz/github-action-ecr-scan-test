package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"log"
	"os"
	"strings"
	"time"
)

var imageTag string
var repository string
var failThreshold = "high"
var ignoreList []string
var region = "us-east-1"

func init() {
	region = os.Getenv("INPUT_AWSREGION")
	os.Setenv("AWS_ACCESS_KEY_ID", os.Getenv("INPUT_AWSACCESSKEY"))
	os.Setenv("AWS_SECRET_ACCESS_KEY", os.Getenv("INPUT_AWSSECRETACCESSKEY"))
	imageTag = os.Getenv("INPUT_IMAGETAG")
	repository = os.Getenv("INPUT_REPOSITORY")
	failThreshold = strings.ToUpper(os.Getenv("INPUT_FAILTHRESHOLD"))
	ignoreList = strings.Split(strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(os.Getenv("INPUT_IGNORELIST"),
		"\n", ""), " ", ""))), ",")
}

func main() {
	findings, err := getFindings()
	if err != nil {
		log.Fatalf("error retrieving scan findings: %s", err.Error())
	}

	if len(findings) > 0 {
		findings = processIgnoreList(findings, ignoreList)
	}

	if len(findings) > 0 {
		log.Println("Vulnerabilities found! Please resolve the vulnerabilities or add them to the ignore list")
		for _, finding := range findings {
			severity := fmt.Sprintf("%v", finding.Severity)
			log.Printf("%s: %s: %s\n", *finding.Name, severity, *finding.Description)
		}
		log.Printf("::set-output name=vulnerabilities::%d", len(findings))
		log.Print("\n")
	}
}

func getFindings() ([]types.ImageScanFinding, error) {
	imageInput := &ecr.DescribeImageScanFindingsInput{
		ImageId: &types.ImageIdentifier{
			ImageTag: &imageTag,
		},
		RepositoryName: &repository,
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := ecr.NewFromConfig(cfg)

	waiter := ecr.NewImageScanCompleteWaiter(client)
	log.Println("Waiting for scan to complete...")
	waiter.Wait(context.TODO(), imageInput, 5*time.Minute)

	paginator := ecr.NewDescribeImageScanFindingsPaginator(client, imageInput, func(o *ecr.DescribeImageScanFindingsPaginatorOptions) {
		o.Limit = 100
	})
	var imageScanFindings []types.ImageScanFinding
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, value := range output.ImageScanFindings.Findings {
			imageScanFindings = append(imageScanFindings, value)
		}
	}

	var filteredFindings []types.ImageScanFinding
	for _, finding := range imageScanFindings {
		switch failThreshold {
		case "CRITICAL":
			if finding.Severity == "CRITICAL" {
				filteredFindings = append(filteredFindings, finding)
			}
		case "HIGH":
			if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
				filteredFindings = append(filteredFindings, finding)
			}
		case "MEDIUM":
			if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" || finding.Severity == "MEDIUM" {
				filteredFindings = append(filteredFindings, finding)
			}
		case "LOW":
			if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" || finding.Severity == "MEDIUM" ||
				finding.Severity == "LOW" {
				filteredFindings = append(filteredFindings, finding)
			}
		case "INFORMATIONAL":
			if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" || finding.Severity == "MEDIUM" ||
				finding.Severity == "LOW" || finding.Severity == "INFORMATIONAL" {
				filteredFindings = append(filteredFindings, finding)
			}
		}
	}
	return filteredFindings, nil
}

func processIgnoreList(imageScanFindings []types.ImageScanFinding, ignoreList []string) []types.ImageScanFinding {
	var filteredFindings []types.ImageScanFinding
	for _, finding := range imageScanFindings {
		itemInIgnoreList := false
		for _, ignoreItem := range ignoreList {
			if *finding.Name == ignoreItem {
				itemInIgnoreList = true
				break
			}
		}
		if !itemInIgnoreList {
			filteredFindings = append(filteredFindings, finding)
		}
	}
	return filteredFindings
}
