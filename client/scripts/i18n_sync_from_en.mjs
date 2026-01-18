import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(scriptDir, '..', 'src', 'i18n')

function loadLocaleObject(filePath) {
  const text = fs.readFileSync(filePath, 'utf8')
  const match = text.match(/const\s+\w+\s*=\s*({[\s\S]*})\s*as\s+const\s*\n\s*\n\s*export\s+default/s)
  if (!match) {
    throw new Error(`Could not parse locale object from ${filePath}`)
  }
  const objExpr = match[1]
  // Evaluate as plain JS object literal.
  // Locale files are generated and should contain only data (no functions).
  // eslint-disable-next-line no-new-func
  return new Function(`"use strict"; return (${objExpr});`)()
}

function isPlainObject(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value)
}

function fillMissingFromBase(target, base) {
  if (!isPlainObject(base)) return

  for (const [key, baseValue] of Object.entries(base)) {
    const hasKey = Object.prototype.hasOwnProperty.call(target, key)

    if (!hasKey) {
      target[key] = isPlainObject(baseValue) ? structuredClone(baseValue) : baseValue
      continue
    }

    const targetValue = target[key]
    if (isPlainObject(baseValue) && isPlainObject(targetValue)) {
      fillMissingFromBase(targetValue, baseValue)
    }
  }
}

function countLeafPaths(obj, prefix = []) {
  const paths = []
  if (!isPlainObject(obj)) return paths
  for (const [k, v] of Object.entries(obj)) {
    if (isPlainObject(v)) {
      paths.push(...countLeafPaths(v, [...prefix, k]))
    } else {
      paths.push([...prefix, k].join('.'))
    }
  }
  return paths
}

function findMissingLeafPaths(target, base, prefix = []) {
  const missing = []
  if (!isPlainObject(base)) return missing

  for (const [k, v] of Object.entries(base)) {
    const nextPrefix = [...prefix, k]
    const hasKey = Object.prototype.hasOwnProperty.call(target, k)

    if (isPlainObject(v)) {
      if (!hasKey || !isPlainObject(target[k])) {
        // Missing entire subtree
        missing.push(...countLeafPaths(v, nextPrefix))
      } else {
        missing.push(...findMissingLeafPaths(target[k], v, nextPrefix))
      }
    } else {
      if (!hasKey) missing.push(nextPrefix.join('.'))
    }
  }

  return missing
}

function writeLocaleFile(filePath, varName, obj) {
  const json = JSON.stringify(obj, null, 2)
  const content = `const ${varName} = ${json} as const\n\nexport default ${varName}\n`
  fs.writeFileSync(filePath, content, 'utf8')
}

const enPath = path.join(root, 'en.ts')
const base = loadLocaleObject(enPath)

const locales = ['nl', 'fr', 'de', 'ru']

for (const locale of locales) {
  const filePath = path.join(root, `${locale}.ts`)
  const target = loadLocaleObject(filePath)
  const missing = findMissingLeafPaths(target, base)

  if (missing.length === 0) {
    console.log(`${locale}: OK (no missing keys)`) // eslint-disable-line no-console
    continue
  }

  console.log(`${locale}: adding ${missing.length} missing key(s) from en`) // eslint-disable-line no-console
  fillMissingFromBase(target, base)
  writeLocaleFile(filePath, locale, target)
}
