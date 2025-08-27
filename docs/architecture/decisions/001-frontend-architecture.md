# Architectural Decision Record: Frontend Architecture

## Date

2025-08-16

## Status

Accepted

## Context

The purpose of this application:

- Decide whether GUI frameworks should be in the Rust ecosystem or traditional React and its environment

## Decision Drivers

1. **Compatibility**: Find a framework that's cross compatible with web, desktop, and mobile
2. **Performance**: Find a framework that's relatively performant
3. **Ease of use/Interest**: Find a framework that will be of interest for everyone and somewhat easy to use

## Decisions for Ecosystems

### Option 1 (Rust ecosystem)

#### Pros

- One language for entire stack / no language "syntax" tripping
- Learn something new with Rust GUI frameworks
- Tauri can help with native integration capabilities across platforms
- Entire stack can be in one language which helps with code-sharing across different stacks

#### Neutral

- Most, if not all, of these frameworks use webview for mobile apps (hybrid apps where they embed web browser components within a native shell) and not native apps

#### Cons

- **Compability + performance issues**: newer frameworks may have stability issues
- **Unfamiliar**: adds some dev time in learning unfamiliar frameworks
- Have steeper learning curves for some frameworks (e.g. iced, leptos, tauri)
- Smaller community than JS-based framework communities and doesn't have a lot of support in regards to niche cases
- Need to learn Tauri in most use cases for cross platform functionality

### Option 2 (JS Ecosystem)

#### Pros

- More mature ecosystem therefore more stable
- No cross compatibility issues for mobile, desktop, and web

#### Cons

- Not a lot of learning potential (Boring)
- Can lead to syntax tripping
- May lead to some performance bottlenecks as virtual DOM gets more complex

## Frameworks Analyzed

### Option 1: Yew + Tauri, a Rust Framework Combo

#### Pros

- **Performant**: Compiles into WebAssembly which is near native to browsers
- Good for computation heavy tasks and rerender heavy applications
- Interop with JS Libraries - can use JS ecosystem when needed with help from `wasm_bindgen` and `web_sys`
- Similar to React with component-based architecture (struct-based components/function-based components)
- Excellent for web UI
- Has a relatively big community

#### Cons

- Continuously being developed (e.g. have to refactor when updating from 0.20 to 0.21)
- Bundles can be quite big as it includes JS libraries if included (e.g. amcharts5, feature heavy JS library is included in the target bundle after compilation)
- Primarily a front-end framework and need to make a separate back-end
- Tauri is needed for cross-platform functionality especially in regards to desktop and mobile

#### Verdict

- Good for high-performance web-applications
- Not good for desktop and mobile applications by itself
- Needs additional support with Tauri for cross-platform functionality
- May not be performant for desktop and mobile

### Option 2: Dioxus, a Rust Framework

#### Pros

- **Cross Platform Development**: Desgined to be able to build and write UI components across all web, desktop, and mobile platforms
- React-like experience
- **Performant**: Compiles into WebAssembly-can be performant for web
- Conceptually similar to how React Native works in terms of mobile
- No need to learn Tauri for cross-platform functionality as it is a feature of the framework to be cross-functional

#### Cons

- Highly experimental and is in active development
- Need to stay updated for latest releases and may need to refactor base code as Dioxus gets updated
- Mobile functionality is still being worked on
- Still in early stages of growth so community is not as mature

#### Verdict

- Good for code sharing across multiple platforms (e.g. web, desktop, mobile) maybe even the best regarding cross platform development so far within the Rust ecosystem
- Experimental and young compared to other UI frameworks.

### Option 3: Leptos + Tauri, a Rust Framework Combo

#### Pros

- **Performant**: Leptos is known for its performance and outperforming some JS frameworks
- **Cross Platform**: With the help of Tauri, can be cross-platform and is a known combination of frameworks that is commonly used
- Leptos is a full-stack framework: can reuse logic between frontend and backend which reduces complexity in regards to codesharing
- No Virtual Dom: more efficient re-renders using fine grained reactivity system

#### Cons

- Need to learn Tauri for cross-platform functionality
- Need to configure Leptos with Tauri to ensure proper communication
- Since Tauri uses webview, there may be some inconsistencies in how web APIs interact between different OS

#### Verdict

- Similar limitations with Yew + Tauri but may be more performant due to no virtual dom and fine grained reactivity with desktop and mobile
- Easy SSR because Leptos is a full-stack framework and not just a front-end framework

### Option 4: React + React Native, React Environment

#### Pros

- Well established community and vast ecosystem in regards to tooling and libraries
- Stable cross-platform development
- Industry standard

#### Cons

- Can be boring
- May not be performant as some Rust frameworks building with WebAssembly

## Alternative Considerations

- Other JS frameworks might not be listed but should be considered (e.g. Svelete + Tauri) as some JS frameworks may be less popular than React and React Native
- Some Rust frameworks may be unknown such as Sycamore in regards to benefits, consequences, and use cases
- Most of the team members haven't developed using some of the Rust frameworks, thus there may be some benefits and consequences overlooked
- Discussion is required whether there is interest in learning something new such as Rust frameworks with the consequence of added dev/learning time vs using more familiar and stable JS frameworks as Rust frameworks undoubtedly will add towards dev time with trial and error

## Decision

### Frontend Framework: **Dioxus**

#### Rationale

1. **Cross-Functionality**: Dioxus uses Tauri under the hood this can work in all different platforms with one code base
2. **General Interest of Use**: Team members showed the most enthusiasm using a new Rust framework
3. **Performance**: As a Rust framework, it is generally performant in regards to being able to compile to WASM and the language advantages itself

## Consequences

### Positive

- **Language Advantages**: Rust doesn't use a GC and has general type safety with ownership giving both performance and safety advantages
- **Cross-Functionality**: Dioxus works in many different platforms and is simple to use in running in different platforms due to shared code base
- **Documentation**: Unlike other newer Rust frameworks, the docs are continuously being updated and has a good amount to get started and for further development

### Negatives

- **Unstability**: Framework is continuously being developed thus newer versions will have breaking changes
- **Learning Curve**: As not many team members use Rust frameworks, there is a learning curve in using Dioxus

### Mitigation

- **Refactoring**: Refactor when newer versions are released depending on our sprints
- **Taking Time to Learn**: Although longer dev time, with the general enthusiasm, taking time to learn a new Rust framework is not an issue

## Specifc Version

```Cargo.toml
[dependencies]
dioxus = { version = "0.6.0" }
```

## Follow-up Decisions Required

- ADR-003: Tech Stack
