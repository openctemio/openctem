### Fixed: a step stays on the organization while its capable sensor restarts

- When an organization has a sensor that can run the tool but it is not online at the moment (restarting, briefly missing heartbeats), routing auto no longer treats the organization as having no sensor: the job waits for that sensor instead of going to the shared fleet. An organization with no capable sensor in any state is unchanged.
