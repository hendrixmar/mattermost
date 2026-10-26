// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import type {AdminConfig, ClientLicense} from '@mattermost/types/config';

import {RESOURCE_KEYS} from 'mattermost-redux/constants/permissions_sysconsole';

import Constants, {LicenseSkus} from 'utils/constants';

import AdminDefinition from './admin_definition';
import type {AdminDefinitionSetting, ConsoleAccess} from './types';

const consoleAccess = {
    read: {[RESOURCE_KEYS.AUTHENTICATION.OPENID]: true},
    write: {[RESOURCE_KEYS.AUTHENTICATION.OPENID]: true},
} as ConsoleAccess;

const enterpriseOpenIdLicense = {IsLicensed: 'true', SkuShortName: LicenseSkus.Enterprise, OpenId: 'true'} as ClientLicense;
const communityLicense: ClientLicense = {IsLicensed: 'false', Cloud: 'false', OpenId: 'false'};
const cloudStarterLicense: ClientLicense = {IsLicensed: 'true', Cloud: 'true', SkuShortName: 'starter'};

const flagOn = {FeatureFlags: {OpenIdAttributeSync: true}} as unknown as Partial<AdminConfig>;
const flagOff = {FeatureFlags: {OpenIdAttributeSync: false}} as unknown as Partial<AdminConfig>;

const openIdState = {openidType: Constants.OPENID_SERVICE};

function getSetting(key: string): AdminDefinitionSetting {
    const settings = (AdminDefinition.authentication.subsections.openid.schema as {settings: AdminDefinitionSetting[]}).settings;
    const setting = settings.find((s) => s.key === key);
    if (!setting) {
        throw new Error(`setting ${key} not found`);
    }
    return setting;
}

function check(setting: AdminDefinitionSetting, prop: 'isHidden' | 'isDisabled', config: Partial<AdminConfig>, state: Record<string, unknown>, license: ClientLicense, access = consoleAccess) {
    const fn = setting[prop];
    if (typeof fn !== 'function') {
        throw new Error(`setting ${setting.key} must have a ${prop} check`);
    }
    return fn(config, state, license, true, access);
}

describe('AdminDefinition - OpenID Connect attribute sync', () => {
    describe('generic OpenID settings', () => {
        test('shows the OpenID Connect settings to an unlicensed self-hosted admin with read access', () => {
            const isHidden = AdminDefinition.authentication.subsections.openid.isHidden;
            if (typeof isHidden !== 'function') {
                throw new Error('OpenID Connect subsection must have a visibility check');
            }

            expect(isHidden({}, openIdState, communityLicense, true, consoleAccess)).toBe(false);
        });

        test('keeps the OpenID Connect settings hidden without read access', () => {
            const isHidden = AdminDefinition.authentication.subsections.openid.isHidden;
            if (typeof isHidden !== 'function') {
                throw new Error('OpenID Connect subsection must have a visibility check');
            }

            expect(isHidden({}, openIdState, communityLicense, true, {...consoleAccess, read: {}} as ConsoleAccess)).toBe(true);
        });
    });

    describe('User attributes sync section', () => {
        const setting = getSetting('OpenIdSettings.CustomProfileAttributes');

        test('shows for generic OpenID with the Enterprise attributes feature and flag, without an OpenID entitlement', () => {
            expect(check(setting, 'isHidden', flagOn, openIdState, {...enterpriseOpenIdLicense, OpenId: 'false'})).toBe(false);
        });

        test.each([
            ['another provider is selected', flagOn, {openidType: Constants.GITLAB_SERVICE}, enterpriseOpenIdLicense],
            ['the flag is off', flagOff, openIdState, enterpriseOpenIdLicense],
            ['the license tier is below Enterprise', flagOn, openIdState, {...enterpriseOpenIdLicense, SkuShortName: LicenseSkus.Professional}],
        ])('hides when %s', (_, config, state, license) => {
            expect(check(setting, 'isHidden', config, state, license as ClientLicense)).toBe(true);
        });

        test('is read-only without write access to OpenID Connect settings', () => {
            expect(check(setting, 'isDisabled', flagOn, openIdState, enterpriseOpenIdLicense)).toBe(false);
            expect(check(setting, 'isDisabled', flagOn, openIdState, enterpriseOpenIdLicense, {...consoleAccess, write: {}} as ConsoleAccess)).toBe(true);
        });
    });

    describe('Additional Scopes', () => {
        const setting = getSetting('OpenIdSettings.AdditionalScopes');

        test('is a text setting shown for generic OpenID without a paid license', () => {
            expect(setting.type).toBe('text');
            expect(check(setting, 'isHidden', flagOn, openIdState, communityLicense)).toBe(false);
            expect(check(setting, 'isHidden', flagOn, openIdState, cloudStarterLicense)).toBe(false);
            expect(check(setting, 'isHidden', flagOn, {openidType: Constants.GOOGLE_SERVICE}, communityLicense)).toBe(true);
        });
    });
});
