<script setup lang="ts">
import { usePreferredReducedMotion } from '@vueuse/core'
import { computed } from 'vue'

const motion = usePreferredReducedMotion()
const still = computed(() => motion.value === 'reduce')

/** The three links a staff badge hangs from, checked root first. */
const chain = [
  { label: 'root key', note: 'you already trust it' },
  { label: 'capability', note: 'may issue for acme.example' },
  { label: 'staff badge', note: 'subject 8f2a…e019' },
]
</script>

<template>
  <!-- What a check walks: a badge is valid because a key signed it whose power
       a root key signed, and nothing in the walk reaches the network. -->
  <figure class="chain" :class="still ? 'chain--still' : ''">
    <figcaption class="flex items-center gap-2 border-b border-edge px-4 py-2.5">
      <span class="size-1.5 rounded-sm bg-accent" aria-hidden="true" />
      <span class="font-mono text-[14px] tracking-wider text-ink-faint">checked offline</span>
    </figcaption>

    <div class="space-y-3 p-4 font-mono text-[14px] leading-relaxed">
      <div v-for="(link, i) in chain" :key="link.label">
        <div
          class="chain__link rounded-lg border p-3"
          :class="
            i === chain.length - 1
              ? 'border-accent/40 bg-accent/8'
              : 'border-edge bg-surface'
          "
          :style="{ animationDelay: `${i * 0.5}s` }"
        >
          <p :class="i === chain.length - 1 ? 'text-ink' : 'text-ink-muted'">
            {{ link.label }}
          </p>
          <p class="text-ink-faint">{{ link.note }}</p>
        </div>
        <p v-if="i < chain.length - 1" class="text-center text-ink-faint" aria-hidden="true">
          signs
        </p>
      </div>

      <p class="pt-1 text-ink-faint">
        no fetch, no clock
      </p>
    </div>
  </figure>
</template>

<style scoped>
.chain {
  overflow: hidden;
  border: 1px solid var(--color-edge);
  border-radius: calc(var(--radius-card) + 2px);
  background: linear-gradient(180deg, var(--lit-from), var(--lit-to));
  box-shadow: var(--lit-shadow);
}

/* Each link settles in turn, the way the walk checks them. */
.chain__link {
  animation: settle 4.5s ease-in-out infinite;
}

@keyframes settle {
  0%,
  22%,
  100% {
    opacity: 0.72;
  }
  8% {
    opacity: 1;
  }
}

.chain--still .chain__link {
  animation: none;
}
</style>
