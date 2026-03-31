#!/bin/bash

# Contract Manifest Validation Script
# This script validates all contract manifests against the schema

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}🔍 Contract Manifest Validation${NC}"
echo "=================================="

# Check if ajv-cli is installed
if ! command -v ajv &> /dev/null; then
    echo -e "${RED}❌ ajv-cli is not installed${NC}"
    echo "Please install it with: npm install -g ajv-cli ajv-formats"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}❌ jq is not installed${NC}"
    echo "Please install it with: sudo apt-get install jq (Ubuntu/Debian) or brew install jq (macOS)"
    exit 1
fi

echo -e "${BLUE}📋 Validating manifests against schema...${NC}"

# Find all manifest files
MANIFESTS=$(find "$CONTRACTS_DIR" -name "*-manifest.json" -not -path "*/node_modules/*")

if [ -z "$MANIFESTS" ]; then
    echo -e "${YELLOW}⚠️  No manifest files found${NC}"
    exit 0
fi

VALID_COUNT=0
TOTAL_COUNT=0

# Validate each manifest
for manifest in $MANIFESTS; do
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    MANIFEST_NAME=$(basename "$manifest" .json)
    
    echo -e "\n${BLUE}📄 Validating $MANIFEST_NAME...${NC}"
    
    # Validate against schema
    if ajv validate --spec=draft2020 -c ajv-formats -s "$CONTRACTS_DIR/contract-manifest-schema.json" -d "$manifest" --verbose 2>/dev/null; then
        echo -e "${GREEN}✅ Schema validation passed${NC}"
        VALID_COUNT=$((VALID_COUNT + 1))
    else
        echo -e "${RED}❌ Schema validation failed${NC}"
        ajv validate --spec=draft2020 -c ajv-formats -s "$CONTRACTS_DIR/contract-manifest-schema.json" -d "$manifest" --verbose
        continue
    fi
    
    # Check required fields
    echo -e "${BLUE}🔍 Checking required fields...${NC}"
    
    REQUIRED_FIELDS=("contract_name" "contract_purpose" "version" "entrypoints" "configuration" "behaviors")
    for field in "${REQUIRED_FIELDS[@]}"; do
        if jq -e "has(\"$field\")" "$manifest" >/dev/null; then
            echo -e "  ${GREEN}✅ $field${NC}"
        else
            echo -e "  ${RED}❌ Missing $field${NC}"
            continue 2
        fi
    done
    
    # Check entrypoints structure
    echo -e "${BLUE}🔍 Checking entrypoints structure...${NC}"
    
    if jq -e '.entrypoints | has("public")' "$manifest" >/dev/null; then
        echo -e "  ${GREEN}✅ entrypoints.public${NC}"
    else
        echo -e "  ${RED}❌ Missing entrypoints.public${NC}"
    fi
    
    if jq -e '.entrypoints | has("view")' "$manifest" >/dev/null; then
        echo -e "  ${GREEN}✅ entrypoints.view${NC}"
    else
        echo -e "  ${RED}❌ Missing entrypoints.view${NC}"
    fi
    
    # Check behaviors structure
    echo -e "${BLUE}🔍 Checking behaviors structure...${NC}"
    
    if jq -e '.behaviors | has("security_features")' "$manifest" >/dev/null; then
        echo -e "  ${GREEN}✅ behaviors.security_features${NC}"
    else
        echo -e "  ${RED}❌ Missing behaviors.security_features${NC}"
    fi
    
    if jq -e '.behaviors | has("access_control")' "$manifest" >/dev/null; then
        echo -e "  ${GREEN}✅ behaviors.access_control${NC}"
    else
        echo -e "  ${RED}❌ Missing behaviors.access_control${NC}"
    fi
    
    # Validate version format
    echo -e "${BLUE}🔍 Checking version format...${NC}"
    
    CURRENT_VERSION=$(jq -r '.version.current' "$manifest")
    SCHEMA_VERSION=$(jq -r '.version.schema' "$manifest")
    
    if [[ "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "  ${GREEN}✅ Current version format: $CURRENT_VERSION${NC}"
    else
        echo -e "  ${RED}❌ Invalid current version format: $CURRENT_VERSION${NC}"
    fi
    
    if [[ "$SCHEMA_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "  ${GREEN}✅ Schema version format: $SCHEMA_VERSION${NC}"
    else
        echo -e "  ${RED}❌ Invalid schema version format: $SCHEMA_VERSION${NC}"
    fi
    
    # Validate authorization values
    echo -e "${BLUE}🔍 Checking authorization values...${NC}"
    
    VALID_AUTH_VALUES=("admin" "signer" "any" "capability" "multisig")
    AUTH_VALUES=$(jq -r '.. | objects | .authorization? // empty' "$manifest" | sort -u)
    
    INVALID_AUTH_FOUND=false
    for auth in $AUTH_VALUES; do
        if [[ ! " ${VALID_AUTH_VALUES[@]} " =~ " ${auth} " ]]; then
            echo -e "  ${RED}❌ Invalid authorization value: $auth${NC}"
            INVALID_AUTH_FOUND=true
        fi
    done
    
    if [ "$INVALID_AUTH_FOUND" = false ]; then
        echo -e "  ${GREEN}✅ All authorization values are valid${NC}"
    fi
    
    # Display contract info
    echo -e "${BLUE}📋 Contract Information:${NC}"
    CONTRACT_NAME=$(jq -r '.contract_name' "$manifest")
    CONTRACT_PURPOSE=$(jq -r '.contract_purpose' "$manifest")
    
    echo -e "  Name: ${GREEN}$CONTRACT_NAME${NC}"
    echo -e "  Purpose: ${GREEN}$CONTRACT_PURPOSE${NC}"
    echo -e "  Version: ${GREEN}$CURRENT_VERSION${NC}"
    echo -e "  Schema: ${GREEN}$SCHEMA_VERSION${NC}"
done

echo -e "\n${BLUE}📊 Validation Summary${NC}"
echo "=================================="
echo -e "Total manifests: ${BLUE}$TOTAL_COUNT${NC}"
echo -e "Valid manifests: ${GREEN}$VALID_COUNT${NC}"
echo -e "Invalid manifests: ${RED}$((TOTAL_COUNT - VALID_COUNT))${NC}"

if [ $VALID_COUNT -eq $TOTAL_COUNT ]; then
    echo -e "\n${GREEN}🎉 All manifests are valid!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some manifests have validation errors${NC}"
    exit 1
fi
