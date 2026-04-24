# Legal Disclaimer and Liability Limitation (v1.0)

## 1. Nature of the Software
Sentinel is a Security Decision Engine (SDE) designed to automate policy enforcement and supply chain risk mitigation. By its nature, Sentinel may perform disruptive actions, including but not limited to:
- Blocking software package installations.
- Preventing Pull Request merges.
- Terminating execution environments (Sandbox).

## 2. No Warranty
SENTINEL IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## 3. High-Risk Activities and "Fail-Closed" Logic
Users of Sentinel acknowledge that the "Fail-Closed" security posture implemented in SPL (Sentinel Playbook Language) may cause operational downtime if misconfigured. The responsibility for defining, testing (via Simulation Mode), and deploying policies lies solely with the end user.

## 4. Third-Party Intelligence and Trust Model
The global reputation data pulled via the `sync` module is provided as telemetry for informational purposes. Sentinel does not guarantee the accuracy of community-sourced threat signals. Users must configure the `TrustModel` according to their organizational risk appetite.

## 5. Automated Response Actions
Sentinel's automated response actions (e.g., `block`, `notify`, `audit`) are executed based on user-defined criteria. Sentinel is not responsible for any direct or indirect consequences of these automated decisions, including but not limited to developer productivity loss or CI/CD pipeline delays.
