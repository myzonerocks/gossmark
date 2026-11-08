<script setup lang="ts">
import BadgeChain from '@/components/BadgeChain.vue'
import CodeTabs from '@/components/CodeTabs.vue'

const sdks = [
  {
    name: 'Swift',
    path: '/docs/sdk/swift',
    line: 'iOS and macOS, through a checksummed XCFramework in the package.',
  },
  {
    name: 'Kotlin',
    path: '/docs/sdk/kotlin',
    line: 'Android, through an AAR carrying the core for every ABI.',
  },
  {
    name: 'TypeScript',
    path: '/docs/sdk/typescript',
    line: 'Browser and Node, through the same core built to wasm.',
  },
  { name: 'C', path: '/docs/sdk/c', line: 'The ABI itself, for any language with a C FFI.' },
]

const guarantees = [
  {
    head: 'Nothing fetches, nothing reads a clock',
    line: 'A verifier is handed its roots, its revocation snapshot and the moment to check against, so a badge checks the same on a plane as it does online.',
  },
  {
    head: 'Organizations issue without a root key',
    line: 'A capability grants permission for a scope, and the scope is checked during verification. Revoking it refuses every badge that flowed from it at once.',
  },
  {
    head: 'No name is anywhere in it',
    line: "A credential's subject is a wallet-bound identifier, so somebody can change their handle without touching their badge.",
  },
]

const pieces = [
  {
    title: 'Credentials',
    line: 'Four kinds, and what a checked badge says.',
    to: '/docs/concepts/credentials',
  },
  {
    title: 'The chain',
    line: 'How an organization issues, within a scope.',
    to: '/docs/concepts/chain',
  },
  {
    title: 'Revocation',
    line: 'Signed snapshots whose sequence only moves forward.',
    to: '/docs/concepts/revocation',
  },
  {
    title: 'Checking offline',
    line: 'Three inputs, no connection, no clock.',
    to: '/docs/concepts/offline',
  },
]
</script>

<template>
  <section class="relative overflow-hidden border-b border-edge">
    <div class="home-glow" aria-hidden="true" />
    <div class="relative mx-auto max-w-6xl px-6 pb-16 pt-16 lg:pt-20">
      <div class="mx-auto max-w-3xl text-center">
        <h1
          class="text-balance text-[2.1rem] font-bold leading-[1.07] tracking-tight sm:text-[2.9rem] lg:text-[3.4rem]"
        >
          The engine behind the checkmark
        </h1>
        <p
          class="mx-auto mt-5 max-w-2xl text-balance text-[1.0625rem] leading-relaxed text-ink-muted sm:text-[1.1875rem]"
        >
          gossmark issues the credentials a badge is made of and checks them, including the
          chain behind one: a staff badge is valid because a key signed it whose power a root
          key signed. All of it works offline.
        </p>

        <div class="mt-9 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
          <RouterLink to="/docs/start/quickstart" class="btn btn-primary">Get started</RouterLink>
          <RouterLink to="/docs/start/install" class="btn btn-quiet">Install</RouterLink>
        </div>
      </div>

      <div class="mt-14 grid items-start gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <CodeTabs />
        <BadgeChain />
      </div>
    </div>
  </section>

  <section class="border-b border-edge">
    <div class="mx-auto grid max-w-7xl gap-px bg-edge px-0 sm:grid-cols-3">
      <div v-for="item in guarantees" :key="item.head" class="bg-ground px-6 py-8 lg:px-8 lg:py-10">
        <h2 class="text-[1.0625rem] font-semibold">{{ item.head }}</h2>
        <p class="mt-2 text-[0.9375rem] leading-relaxed text-ink-muted">{{ item.line }}</p>
      </div>
    </div>
  </section>

  <section class="border-b border-edge">
    <div class="mx-auto max-w-7xl px-6 py-14 lg:py-20">
      <p class="font-mono text-[12px] uppercase tracking-[0.2em] text-ink-faint">How a badge holds up</p>
      <div class="mt-8 grid gap-px bg-edge sm:grid-cols-2 lg:grid-cols-4">
        <RouterLink
          v-for="piece in pieces"
          :key="piece.title"
          :to="piece.to"
          class="group bg-ground p-6 transition-colors hover:bg-surface"
        >
          <span class="flex items-center justify-between text-[1.0625rem] font-semibold">
            {{ piece.title }}
            <span
              class="text-ink-faint transition-transform group-hover:translate-x-0.5 group-hover:text-accent"
              aria-hidden="true"
            >
              &rarr;
            </span>
          </span>
          <span class="mt-2 block text-[0.9375rem] leading-relaxed text-ink-muted">
            {{ piece.line }}
          </span>
        </RouterLink>
      </div>
    </div>
  </section>

  <section class="border-b border-edge">
    <div class="mx-auto max-w-7xl px-6 py-14 lg:py-20">
      <p class="font-mono text-[12px] uppercase tracking-[0.2em] text-ink-faint">SDKs</p>
      <h2 class="mt-3 max-w-2xl text-[1.75rem] font-bold leading-tight tracking-tight sm:text-3xl">
        Swift, Kotlin, TypeScript, Go, C
      </h2>
      <div class="mt-8 grid gap-px bg-edge sm:grid-cols-2 lg:grid-cols-4">
        <RouterLink
          v-for="sdk in sdks"
          :key="sdk.name"
          :to="sdk.path"
          class="group bg-ground p-6 transition-colors hover:bg-surface"
        >
          <span class="flex items-center justify-between text-[1.0625rem] font-semibold">
            {{ sdk.name }}
            <span
              class="text-ink-faint transition-transform group-hover:translate-x-0.5 group-hover:text-accent"
              aria-hidden="true"
            >
              &rarr;
            </span>
          </span>
          <span class="mt-2 block text-[0.9375rem] leading-relaxed text-ink-muted">
            {{ sdk.line }}
          </span>
        </RouterLink>
      </div>
    </div>
  </section>

  <section>
    <div class="mx-auto max-w-7xl px-6 py-16 lg:py-20">
      <div class="lit flex flex-col gap-6 rounded-card p-8 lg:flex-row lg:items-center lg:p-10">
        <div class="max-w-xl">
          <h2 class="text-[1.5rem] font-bold tracking-tight">Where gossmark stops</h2>
          <p class="mt-3 text-[1.0625rem] leading-relaxed text-ink-muted">
            It does not decide who deserves a badge, store one, or serve a revocation list.
            You issue, you distribute, you host. It signs and it checks.
          </p>
        </div>
        <RouterLink to="/docs/about" class="btn btn-quiet shrink-0 lg:ml-auto">
          What it's for
        </RouterLink>
      </div>
    </div>
  </section>
</template>

<style scoped>
/* One light above the hero, strongest at the top edge and gone by the fold. */
.home-glow {
  position: absolute;
  inset: -40% 0 auto 0;
  height: 620px;
  background: radial-gradient(
    60% 50% at 50% 50%,
    color-mix(in oklab, var(--color-accent) calc(var(--glow) * 100%), transparent),
    transparent 70%
  );
  pointer-events: none;
}
</style>
