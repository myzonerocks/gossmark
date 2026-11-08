<script setup lang="ts">
withDefaults(defineProps<{ size?: number }>(), { size: 26 })
</script>

<template>
  <!-- A check inside a seal, with the notch of a chain link: a badge is valid
       because a key signed it whose power a root key signed. -->
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 32 32"
    fill="none"
    class="shrink-0"
    aria-hidden="true"
  >
    <path
      d="M16 2.8 28 8.2v7.1c0 7-4.9 12.4-12 14.2C8.9 27.7 4 22.3 4 15.3V8.2Z"
      stroke="currentColor"
      stroke-width="2.1"
      stroke-linejoin="round"
      opacity="0.9"
    />
    <path
      d="m10.6 16.1 3.6 3.7 7.2-7.6"
      stroke="var(--color-accent)"
      stroke-width="2.8"
      stroke-linecap="round"
      stroke-linejoin="round"
    />
  </svg>
</template>
