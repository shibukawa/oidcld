<script setup lang="ts">
import { computed } from "vue";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { useI18n } from "vue-i18n";
import githubIcon from "./assets/GitHub_Invertocat_White_Clearspace.svg";
import { setLocale, supportedLocales, type SupportedLocale } from "./i18n";

const route = useRoute();
const { t, locale } = useI18n();

const navigation = computed(() => [
    {
        label: t("app.nav.certificateAuthority"),
        to: "/certificate-authority",
    },
    {
        label: t("app.nav.openidConnect"),
        to: "/openid-connect",
    },
    {
        label: t("app.nav.reverseProxy"),
        to: "/reverse-proxy",
    },
    {
        label: t("app.nav.accessLogs"),
        to: "/reverse-proxy/logs",
    },
]);

const languageOptions = supportedLocales.map((value) => ({
    value,
    labelKey: `app.language.${value}` as const,
}));

function selectLocale(value: SupportedLocale) {
    setLocale(value);
}
</script>

<template>
    <div class="shell">
        <aside class="sidebar">
            <div class="sidebar-topbar">
                <div class="sidebar-orb sidebar-orb-muted"></div>
                <div class="sidebar-orb sidebar-orb-warm"></div>
                <div class="sidebar-orb sidebar-orb-bright"></div>
            </div>

            <div class="brand-block panel-sheen">
                <p class="eyebrow">{{ t("app.brand.eyebrow") }}</p>
                <h1>{{ t("app.brand.title") }}</h1>
                <p class="lede">{{ t("app.brand.lede") }}</p>
            </div>

            <nav class="nav">
                <RouterLink
                    v-for="item in navigation"
                    :key="item.to"
                    :to="item.to"
                    class="nav-link"
                    :class="{ 'nav-link-active': route.path === item.to }"
                >
                    <p class="nav-label">{{ item.label }}</p>
                </RouterLink>
            </nav>

            <div class="sidebar-footer">
                <div class="language-switcher">
                    <div
                        class="language-toggle"
                        role="group"
                        :aria-label="t('app.language.label')"
                    >
                        <button
                            v-for="option in languageOptions"
                            :key="option.value"
                            type="button"
                            class="language-button"
                            :class="{
                                'language-button-active':
                                    locale === option.value,
                            }"
                            @click="selectLocale(option.value)"
                        >
                            {{ t(option.labelKey) }}
                        </button>
                    </div>
                </div>

                <a
                    class="sidebar-icon-link"
                    href="https://github.com/shibukawa/oidcld"
                    target="_blank"
                    rel="noreferrer"
                    :aria-label="t('app.githubAria')"
                >
                    <img class="sidebar-icon" :src="githubIcon" alt="" />
                </a>
            </div>
        </aside>

        <main class="content">
            <RouterView />
        </main>
    </div>
</template>

<style scoped>
.nav-link-active {
    background: linear-gradient(135deg, #0f7c8b, #1559a5);
    border-color: rgba(186, 227, 255, 0.34);
    box-shadow: 0 24px 44px rgba(4, 16, 43, 0.3);
}

.nav-link-active .nav-eyebrow,
.nav-link-active .nav-label {
    color: #f5fbff;
}
</style>
