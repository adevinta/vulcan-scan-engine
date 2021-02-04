/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
)

// AssettypeInformer provides required functions to query the current checktypes
// in vulcan-core and the assettypes they can accept.
type AssettypeInformer interface {
	IndexAssettypes(ctx context.Context, path string) (*http.Response, error)
	DecodeAssettypeCollection(resp *http.Response) (client.AssettypeCollection, error)
}

// ChecktypesByAssettypes is used as a lookup table to check if a checktype can
// be run against a concrete assettype.
type ChecktypesByAssettypes map[string]map[string]struct{}

// ChecktypeCreator creates the checks payload to be send to vulcan-core from a
// scan creation request.
type CheckCreator struct {
	assettypeInformer AssettypeInformer
}

func (c *CheckCreator) checktypesByAssettype(ctx context.Context) (ChecktypesByAssettypes, error) {
	resp, err := c.assettypeInformer.IndexAssettypes(ctx, client.IndexAssettypesPath())
	if err != nil {
		return nil, err
	}

	assettypes, err := c.assettypeInformer.DecodeAssettypeCollection(resp)
	if err != nil {
		return nil, err
	}
	ret := ChecktypesByAssettypes{}
	for _, a := range assettypes {
		if a.Assettype == nil {
			continue
		}
		if _, ok := ret[*a.Assettype]; !ok {
			ret[*a.Assettype] = map[string]struct{}{}
		}
		for _, c := range a.Name {
			ret[*a.Assettype][c] = struct{}{}
		}
	}
	return ret, nil
}

func (c *CheckCreator) CreateScanChecks(ctx context.Context, scan api.Scan) ([]*client.CheckPayload, error) {
	// Get current checktype and definitions.
	checktypesInfo, err := c.checktypesByAssettype(ctx)
	if err != nil {
		return nil, err
	}
	checks := []*client.CheckPayload{}
	if scan.TargetGroups == nil {
		return nil, fmt.Errorf("unexpected nil in field ChecktypesGroup")
	}
	for _, tg := range *scan.TargetGroups {
		groupChecks, err := c.checksForTargetsChecktypesGroups(scan.Tag, tg, checktypesInfo)
		if err != nil {
			return nil, err
		}
		checks = append(checks, groupChecks...)
	}
	return checks, nil
}

func (c *CheckCreator) checksForTargetsChecktypesGroups(tag *string, group api.TargetsChecktypesGroup, checktypesInfo ChecktypesByAssettypes) ([]*client.CheckPayload, error) {
	checks := []*client.CheckPayload{}
	for _, a := range group.TargetGroup.Targets {
		for _, c := range group.ChecktypesGroup.Checktypes {
			validChecksForAsset, ok := checktypesInfo[a.Type]
			if !ok {
				return nil, fmt.Errorf("invalid assettype %s", a.Type)
			}
			_, ok = validChecksForAsset[c.Name]
			if !ok {
				// If the check is not present in the map for assettype it means
				// the checktype cannot run against this asset.
				continue
			}
			// It's better to assign those values to single variables even if it
			// is not needed just to make clear the order in which the options
			// are overridden. Concretely one variable overrides the options of
			// the previous ones if they define the same fields.
			checktypeOpts := c.Options
			targetGroupOpts := group.TargetGroup.Options
			targetOpts := a.Options
			options, err := buildOptionsForCheck(checktypeOpts, targetGroupOpts, targetOpts)
			if err != nil {
				return nil, err
			}
			name := c.Name
			assetType := a.Type
			check := client.CheckPayload{
				Check: &client.CheckData{
					ChecktypeName: &name,
					Options:       &options,
					Target:        a.Identifier,
					Assettype:     &assetType,
					Tag:           tag,
				},
			}
			checks = append(checks, &check)
		}
	}
	return checks, nil
}

func buildOptionsForCheck(checktypeOpts, targetGroupOpts, targetOpts string) (string, error) {
	totalOptions := map[string]interface{}{}
	if checktypeOpts != "" {
		json.Unmarshal([]byte(checktypeOpts), &totalOptions)
	}
	if targetGroupOpts != "" {
		aux := map[string]interface{}{}
		if err := json.Unmarshal([]byte(targetGroupOpts), &aux); err != nil {
			return "", nil
		}
		totalOptions = mergeOptions(totalOptions, aux)
	}
	if targetOpts != "" {
		aux := map[string]interface{}{}
		if err := json.Unmarshal([]byte(targetOpts), &aux); err != nil {
			return "", nil
		}
		totalOptions = mergeOptions(totalOptions, aux)
	}
	content, err := json.Marshal(totalOptions)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
